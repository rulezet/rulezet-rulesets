rule jpeg_2000: JPEG2000 {
  meta:
    author = "Jaume Martin"

  strings:
    $a = { 00 00 00 0C 6A 50 20 20 0D 0A }

  condition:
    $a at 0
}