rule libavcodec_asus_v1_v2_scantab__8_byt_64_ {
  strings:
    $a0 = { 00 08 01 09 10 18 11 19 02 0a 03 0b 12 1a 13 1b 04 0c 05 0d 20 28 21 29 06 0e 07 0f 14 1c 15 1d 22 2a 23 2b 30 38 31 39 16 1e 17 1f 24 2c 25 2d 32 3a 33 3b 26 2e 27 2f 34 3c 35 3d 36 3e 37 3f }

  condition:
    $a0
}