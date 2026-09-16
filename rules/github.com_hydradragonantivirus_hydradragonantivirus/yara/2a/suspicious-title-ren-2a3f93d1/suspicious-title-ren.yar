rule suspicious_title_ren: PDF raw {
  meta:
    author  = "Glenn Edwards (@hiddenillusion)"
    version = "0.1"
    weight  = 4

  strings:
    $magic  = "%PDF"
    $header = /%PDF-1\.(3|4|6)/

    $title0 = "who cis"
    $title1 = "P66N7FF"
    $title2 = "Fohcirya"

  condition:
    $magic in (0..1024) and $header and 1 of ($title*)
}