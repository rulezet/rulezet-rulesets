rule YUV_to_RGB_dither_8x8_220_4__8_byt_64_ {
  strings:
    $a0 = { 00 6b 03 bb 00 7d 06 d4 27 07 56 1c 31 0b 66 24 01 9e 00 83 03 b4 01 97 44 13 34 0c 51 19 40 11 00 77 05 cb 00 71 04 c3 2d 09 60 21 2a 08 5b 1e 02 ac 01 90 02 a5 00 89 4d 17 3c 0f 48 15 38 0e }

  condition:
    $a0
}