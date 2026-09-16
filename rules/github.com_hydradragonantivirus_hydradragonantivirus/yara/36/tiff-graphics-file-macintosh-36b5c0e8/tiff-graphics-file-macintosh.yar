import "pe"
rule _TIFF_Graphics_file_Macintosh_ {
  meta:
    description = "TIFF Graphics file (Macintosh)"

  strings:
    $0 = { 4D 4D 00 }

  condition:
    $0 at pe.entry_point
}