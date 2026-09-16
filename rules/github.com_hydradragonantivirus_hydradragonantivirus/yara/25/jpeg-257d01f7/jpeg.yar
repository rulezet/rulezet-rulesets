rule jpeg: JFIF JPE JPEG JPG {
  meta:
    author = "Jaume Martin"

  strings:
    $a = { FF D8 FF E0 ?? ?? 4A 46 49 46 00 }

  condition:
    $a at 0
}