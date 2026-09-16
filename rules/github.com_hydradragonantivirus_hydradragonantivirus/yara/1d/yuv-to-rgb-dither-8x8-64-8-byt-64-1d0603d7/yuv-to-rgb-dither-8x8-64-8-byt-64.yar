rule YUV_to_RGB_dither_8x8_64__8_byt_64_ {
  strings:
    $a0 = { 00 30 0c 3c 03 33 0f 3f 20 10 2c 1c 23 13 2f 1f 08 38 04 34 0b 3b 07 37 28 18 24 14 2b 1b 27 17 02 32 0e 3e 01 31 0d 3d 22 12 2e 1e 21 11 2d 1d 0a 3a 06 36 09 39 05 35 2a 1a 26 16 29 19 25 15 }

  condition:
    $a0
}