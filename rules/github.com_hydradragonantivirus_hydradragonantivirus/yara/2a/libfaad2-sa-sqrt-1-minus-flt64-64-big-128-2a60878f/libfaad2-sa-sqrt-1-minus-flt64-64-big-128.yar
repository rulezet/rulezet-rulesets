rule libfaad2_sa_sqrt_1_minus__flt64___64_big_128_ {
  strings:
    $a0 = { 3f f0 00 00 00 00 00 00 3f f0 00 00 00 00 00 00 3f ef f5 b6 68 ba dd 14 3f ef 7d 79 54 a2 10 2d 3f ef eb 8e fd c5 79 58 3f ee b4 01 12 be 62 6b 3f ef d7 59 03 62 9c 3e 3f ec a1 3f ed ce 1b a4 3f ef af 6f d9 1a a7 bb 3f ea 76 3c dc 0f 9c 10 3f ef 61 99 12 93 b4 05 3f e6 9a 1d 08 5f b1 27 3f ee cc c1 f8 66 0b 55 3f dd 04 bc 67 cf c7 ff 3f ed ba f4 4f 3f 24 d0 00 00 00 00 00 00 00 00 }

  condition:
    $a0
}