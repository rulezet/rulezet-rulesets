rule suspicious_embed_ren: PDF {
  meta:
    author  = "Glenn Edwards (@hiddenillusion)"
    version = "0.1"
    ref     = "https://feliam.wordpress.com/2010/01/13/generic-pdf-exploit-hider-embedpdf-py-and-goodbye-av-detection-012010/"
    weight  = 2

  strings:
    $magic = "%PDF"

    $meth0   = /\/Launch/
    $meth1   = /\/GoTo(E|R)/      $attrib0 = /\/URL /
    $attrib1 = /\/Action/
    $attrib2 = /\/Filespec/

  condition:
    $magic at 0 and 1 of ($meth*) and 2 of ($attrib*)
}