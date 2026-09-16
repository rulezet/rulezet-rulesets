rule YUV_to_RGB_dither_8x8_128__8_byt_64_ {
  strings:
    $a0 = { 44 24 5c 3c 42 22 5a 3a 14 74 0c 6c 12 72 0a 6a 54 34 4c 2c 52 32 4a 2a 00 60 18 78 06 66 1e 7e 40 20 58 38 46 26 5e 3e 10 70 08 68 16 76 0e 6e 50 30 48 28 56 36 4e 2e 04 64 1c 7c 02 62 1a 7a }

  condition:
    $a0
}