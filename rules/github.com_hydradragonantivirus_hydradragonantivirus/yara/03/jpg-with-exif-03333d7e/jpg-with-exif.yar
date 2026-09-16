rule jpg_with_EXIF: JPG {
  meta:
    author = "Jaume Martin"

  strings:
    $a = { FF D8 FF E1 ?? ?? 45 78 69 66 00 }

  condition:
    $a at 0
}