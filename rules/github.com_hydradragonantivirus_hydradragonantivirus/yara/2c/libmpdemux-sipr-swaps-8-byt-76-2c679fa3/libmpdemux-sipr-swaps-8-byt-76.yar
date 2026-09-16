rule libmpdemux_sipr_swaps__8_byt_76_ {
  strings:
    $a0 = { 00 3f 01 16 02 2c 03 5a 05 51 07 1f 08 56 09 3a 0a 24 0c 44 0d 27 0e 49 0f 35 10 45 11 39 13 58 14 22 15 47 18 2e 19 5e 1a 36 1c 4b 1d 32 20 46 21 5c 23 4a 26 55 28 38 2a 57 2b 41 2d 3b 30 4f 31 5d 33 59 37 5f 3d 4c 43 53 4d 50 }

  condition:
    $a0
}