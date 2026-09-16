rule swscale_perm_rgb__8_byt_64_ {
  strings:
    $a0 = { 00 01 10 02 03 11 04 05 12 06 07 13 08 09 14 0a 0b 15 0c 0d 16 0e 0f 17 18 19 1a 1b 1c 1d 1e 1f 10 11 12 13 14 15 16 17 00 01 18 02 03 19 04 05 1a 06 07 1b 08 09 1c 0a 0b 1d 0c 0d 1e 0e 0f 1f }

  condition:
    $a0
}