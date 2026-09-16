rule libfaad2_log2_tab__flt32___32_big_260_ {
  strings:
    $a0 = { 00 00 00 00 3c b7 3c b4 3d 35 d6 9c 3d 87 59 c5 3d b3 1f b8 3d de 42 12 3e 04 62 c4 3e 19 57 4f 3e 2e 00 d2 3e 42 61 5f 3e 56 7a f1 3e 6a 4f 72 3e 7d e0 b6 3e 88 98 3f 3e 92 20 3d 3e 9b 89 26 3e a4 d3 c2 3e ae 00 d2 3e b7 11 0e 3e c0 05 2b 3e c8 dd d4 3e d1 9b b0 3e da 3f 60 3e e2 c9 7d 3e eb 3a 9f 3e f3 93 55 3e fb d4 2b 3f 01 fe d4 3f 06 08 28 3f 0a 06 50 3f 0d f9 89 3f 11 e2 0f 3f 15 c0 1a 3f 19 93 e3 3f 1d 5d a0 3f 21 1d 84 3f 24 d3 c2 3f 28 80 8c 3f 2c 24 11 3f 2f be 80 3f 33 50 04 3f 36 d8 cb 3f 3a 58 ff 3f 3d d0 c8 3f 41 40 4f 3f 44 a7 ba 3f 48 07 31 3f 4b 5e d7 3f 4e ae d0 3f 51 f7 40 3f 55 38 48 3f 58 72 09 3f 5b a4 a4 3f 5e d0 39 3f 61 f4 e5 3f 65 12 c7 3f 68 29 fb 3f 6b 3a 9f 3f 6e 44 cd 3f 71 48 a1 3f 74 46 36 3f 77 3d a4 3f 7a 2f 04 3f 7d 1a 71 3f 80 00 00 }

  condition:
    $a0
}