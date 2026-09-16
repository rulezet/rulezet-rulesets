import "pe"
rule _JPEG__GIF_library_file_ {
  meta:
    description = "JPEG & GIF library file"

  strings:
    $0 = { 00 05 16 07 00 02 00 00 }

  condition:
    $0 at pe.entry_point
}