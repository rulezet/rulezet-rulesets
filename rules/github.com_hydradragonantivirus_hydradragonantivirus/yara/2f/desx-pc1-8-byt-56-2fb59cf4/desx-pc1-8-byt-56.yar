rule DESX_pc1__8_byt_56_ {
  strings:
    $a0 = { 38 30 28 20 18 10 08 00 39 31 29 21 19 11 09 01 3a 32 2a 22 1a 12 0a 02 3b 33 2b 23 3e 36 2e 26 1e 16 0e 06 3d 35 2d 25 1d 15 0d 05 3c 34 2c 24 1c 14 0c 04 1b 13 0b 03 }

  condition:
    $a0
}