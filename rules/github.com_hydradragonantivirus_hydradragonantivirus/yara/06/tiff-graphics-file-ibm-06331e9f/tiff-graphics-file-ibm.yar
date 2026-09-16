import "pe"
rule _TIFF_Graphics_file_IBM_ {
  meta:
    description = "TIFF Graphics file (IBM)"

  strings:
    $0 = "II*"

  condition:
    $0 at pe.entry_point
}