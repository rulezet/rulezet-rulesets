import "pe"
rule _HSI_JPEG_graphics_file_ {
  meta:
    description = "HSI JPEG graphics file"

  strings:
    $0 = { 68 73 69 31 00 00 }

  condition:
    $0 at pe.entry_point
}