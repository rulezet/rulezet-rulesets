rule libavcodec_imc_quantizer1__flt64___64_big_256_ {
  strings:
    $a0 = { 3f eb 04 9a 9e d2 3d a5 3f de 4f 2f 1c f9 0a 18 3f f7 2c 75 3e 70 7e 17 3f d1 53 c9 a0 f3 55 22 3f e7 d2 dc c1 61 89 b3 3f f3 df 31 f4 6e d2 46 3f fd 87 1a 3b 14 a9 04 00 00 00 00 00 00 00 00 3f eb cc f0 7e 57 c9 c0 3f de 80 73 62 a3 38 54 3f f7 a6 ce 35 82 98 cc 3f d0 6e 3b 3c 41 23 e2 3f e8 2f 53 3f 42 35 2f 3f f5 2a f2 6c 99 86 4e 40 00 46 69 05 7d 17 83 00 00 00 00 00 00 00 00 3f e8 49 08 21 8c 97 a8 3f e3 ed 63 3f eb 52 74 3f f4 57 55 bc ca f7 0a 3f d6 44 0f 23 89 72 04 3f e8 1a 06 a1 84 ca 80 3f f2 69 8a a8 65 0e 78 3f fa 0e 3c d9 a5 22 64 00 00 00 00 00 00 00 00 3f e8 7c fc 3f 81 1f 4f 3f e4 a0 f2 be ce dd 48 3f f4 38 9f 83 be 66 02 3f d6 1c 5c 61 d5 b2 fa 3f e8 71 73 7f ff 69 ad 3f f3 6e 73 e6 81 a9 b9 3f fc 38 d9 14 d9 ab d8 00 00 00 00 00 00 00 00 }

  condition:
    $a0
}