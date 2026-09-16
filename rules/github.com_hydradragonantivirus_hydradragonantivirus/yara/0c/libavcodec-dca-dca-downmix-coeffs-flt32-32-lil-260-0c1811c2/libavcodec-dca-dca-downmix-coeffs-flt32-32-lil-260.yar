rule libavcodec_dca_dca_downmix_coeffs__flt32___32_lil_260_ {
  strings:
    $a0 = { 00 00 80 3f d1 11 7d 3f 9c bc 78 3f f9 ad 71 3f 98 d2 6a 3f 05 29 64 3f d7 af 5d 3f ac 65 57 3f 31 49 51 3f 18 59 4b 3f 21 94 45 3f 11 f9 3f 3f b8 86 3a 3f ef 3b 35 3f 96 17 30 3f 96 18 2b 3f e0 3d 26 3f 6c 86 21 3f 39 f1 1c 3f 50 7d 18 3f bf 29 14 3f 9a f5 0f 3f fd df 0b 3f 0b e8 07 3f ec 0c 04 3f ce 4d 00 3f b6 b3 e4 3e b4 d4 cb 3e 1a aa b5 3e 9b e8 a1 3e 1c 4d 90 3e cc 9b 80 3e bb 3e 65 3e 9b 50 4c 3e 87 18 36 3e 06 4b 22 3e d3 a4 10 3e f9 e9 00 3e 15 ca e5 3d cd cc cc 3d 38 87 b6 3d ad ad a2 3d bf fc 90 3d 56 38 81 3d 45 73 59 3d 2b f6 36 3d 69 f1 19 3d e2 86 01 3d 73 f7 d9 3c 63 65 b7 3c fc 4e 9a 3c 9f d5 81 3c f1 7b 5a 3c dd d4 37 3c c8 ac 1a 3c 8a 24 02 3c 9c 44 b8 3b a6 73 82 3b 9f b4 38 3b f2 c2 02 3b e5 24 b9 3a 6f 12 83 3a 1b 62 03 3a f8 b1 83 39 00 00 00 00 }

  condition:
    $a0
}