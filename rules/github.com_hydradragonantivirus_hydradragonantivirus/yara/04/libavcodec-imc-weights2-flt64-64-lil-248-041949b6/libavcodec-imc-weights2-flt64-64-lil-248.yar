rule libavcodec_imc_weights2__flt64___64_lil_248_ {
  strings:
    $a0 = { 7f dc 3c dd 92 7f 6a 3f 11 bb be 28 a4 a9 6c 3f 9d 23 d9 c0 a9 51 70 3f aa 82 0f 2d cb 3a 60 3f 31 84 52 6a e5 14 53 3f 96 0a e8 8d ac 5f 5d 3f 0d 12 89 df a0 ff 56 3f 05 57 b3 ad ea d5 55 3f 91 8b de 67 64 a9 58 3f f0 b7 66 c0 93 f5 5f 3f ed 52 fa 74 02 bb 66 3f 4a b4 e4 f1 b4 fc 70 3f 07 6d 28 6b 8a b6 79 3f cd e2 ac 25 70 2d 83 3f 86 5e da cb 11 8d 91 3f 5c 96 0a 85 63 f1 96 3f ae 78 34 1f 21 14 9d 3f a7 7e 39 0e 17 14 a5 3f 82 53 1f 48 de 39 a8 3f 8d 3c b5 9f 31 38 ab 3f b9 d3 e7 b4 b8 10 b1 3f 70 35 fc b8 47 80 b4 3f 1a e6 5f 26 e5 49 b5 3f e5 22 63 5a 40 0d b6 3f 8d 52 53 dc 02 53 b9 3f 79 95 b5 4d f1 b8 bc 3f c2 be 9d 44 84 7f bd 3f b2 2b 2d 23 f5 9e be 3f 6f 62 48 4e 26 6e c1 3f 69 00 6f 81 04 c5 c3 3f 89 5e 46 b1 dc d2 c4 3f }

  condition:
    $a0
}