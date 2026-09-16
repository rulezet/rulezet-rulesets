rule ogg: OGG {
  meta:
    author    = "Jaume Martin"
    file_info = "Ogg Vorbis Codec"

  strings:
    $a = { 4F 67 67 53 00 02 00 00 00 00 00 00 00 00 }

  condition:
    $a at 0
}