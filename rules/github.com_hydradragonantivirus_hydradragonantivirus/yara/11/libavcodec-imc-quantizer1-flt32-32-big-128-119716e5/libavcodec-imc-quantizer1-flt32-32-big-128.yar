rule libavcodec_imc_quantizer1__flt32___32_big_128_ {
  strings:
    $a0 = { 3f 58 24 d5 3e f2 79 79 3f b9 63 aa 3e 8a 9e 4d 3f 3e 96 e6 3f 9e f9 90 3f ec 38 d2 00 00 00 00 3f 5e 67 84 3e f4 03 9b 3f bd 36 72 3e 83 71 da 3f 41 7a 9a 3f a9 57 93 40 02 33 48 00 00 00 00 3f 42 48 41 3f 1f 6b 1a 3f a2 ba ae 3e b2 20 79 3f 40 d0 35 3f 93 4c 55 3f d0 71 e7 00 00 00 00 3f 43 e7 e2 3f 25 07 96 3f a1 c4 fc 3e b0 e2 e3 3f 43 8b 9c 3f 9b 73 9f 3f e1 c6 c9 00 00 00 00 }

  condition:
    $a0
}