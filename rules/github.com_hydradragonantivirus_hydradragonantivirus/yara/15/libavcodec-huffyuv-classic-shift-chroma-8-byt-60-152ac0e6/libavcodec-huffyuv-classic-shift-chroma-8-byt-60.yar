rule libavcodec_huffyuv_classic_shift_chroma__8_byt_60_ {
  strings:
    $a0 = { 42 24 25 26 27 28 29 4b 4c 4d 6e ef 90 51 52 53 54 55 76 b7 38 39 58 59 38 59 9a 39 3a 39 1a 8d 39 38 3a 39 3a 39 b8 77 d6 f5 74 53 52 31 50 4f 4e 4d 2c 4b 29 28 27 26 25 24 22 00 }

  condition:
    $a0
}