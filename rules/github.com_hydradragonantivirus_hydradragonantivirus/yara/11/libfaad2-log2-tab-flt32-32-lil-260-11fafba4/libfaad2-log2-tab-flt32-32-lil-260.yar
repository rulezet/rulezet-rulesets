rule libfaad2_log2_tab__flt32___32_lil_260_ {
  strings:
    $a0 = { 00 00 00 00 b4 3c b7 3c 9c d6 35 3d c5 59 87 3d b8 1f b3 3d 12 42 de 3d c4 62 04 3e 4f 57 19 3e d2 00 2e 3e 5f 61 42 3e f1 7a 56 3e 72 4f 6a 3e b6 e0 7d 3e 3f 98 88 3e 3d 20 92 3e 26 89 9b 3e c2 d3 a4 3e d2 00 ae 3e 0e 11 b7 3e 2b 05 c0 3e d4 dd c8 3e b0 9b d1 3e 60 3f da 3e 7d c9 e2 3e 9f 3a eb 3e 55 93 f3 3e 2b d4 fb 3e d4 fe 01 3f 28 08 06 3f 50 06 0a 3f 89 f9 0d 3f 0f e2 11 3f 1a c0 15 3f e3 93 19 3f a0 5d 1d 3f 84 1d 21 3f c2 d3 24 3f 8c 80 28 3f 11 24 2c 3f 80 be 2f 3f 04 50 33 3f cb d8 36 3f ff 58 3a 3f c8 d0 3d 3f 4f 40 41 3f ba a7 44 3f 31 07 48 3f d7 5e 4b 3f d0 ae 4e 3f 40 f7 51 3f 48 38 55 3f 09 72 58 3f a4 a4 5b 3f 39 d0 5e 3f e5 f4 61 3f c7 12 65 3f fb 29 68 3f 9f 3a 6b 3f cd 44 6e 3f a1 48 71 3f 36 46 74 3f a4 3d 77 3f 04 2f 7a 3f 71 1a 7d 3f 00 00 80 3f }

  condition:
    $a0
}