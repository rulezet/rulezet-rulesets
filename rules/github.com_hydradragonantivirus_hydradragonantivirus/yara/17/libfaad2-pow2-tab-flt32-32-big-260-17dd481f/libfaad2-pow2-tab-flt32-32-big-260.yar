rule libfaad2_pow2_tab__flt32___32_big_260_ {
  strings:
    $a0 = { 3f 80 00 00 3f 81 64 d2 3f 82 cd 87 3f 84 3a 29 3f 85 aa c3 3f 87 1f 62 3f 88 98 0f 3f 8a 14 d5 3f 8b 95 c2 3f 8d 1a df 3f 8e a4 3a 3f 90 31 dc 3f 91 c3 d3 3f 93 5a 2b 3f 94 f4 f0 3f 96 94 2d 3f 98 37 f0 3f 99 e0 46 3f 9b 8d 3a 3f 9d 3e da 3f 9e f5 32 3f a0 b0 51 3f a2 70 43 3f a4 35 16 3f a5 fe d7 3f a7 cd 94 3f a9 a1 5b 3f ab 7a 3a 3f ad 58 3f 3f af 3b 79 3f b1 23 f6 3f b3 11 c4 3f b5 04 f3 3f b6 fd 92 3f b8 fb af 3f ba ff 5b 3f bd 08 a4 3f bf 17 9a 3f c1 2c 4d 3f c3 46 cd 3f c5 67 2a 3f c7 8d 75 3f c9 b9 be 3f cb ec 15 3f ce 24 8c 3f d0 63 34 3f d2 a8 1e 3f d4 f3 5b 3f d7 44 fd 3f d9 9d 16 3f db fb b8 3f de 60 f5 3f e0 cc df 3f e3 3f 89 3f e5 b9 07 3f e8 39 6a 3f ea c0 c7 3f ed 4f 30 3f ef e4 ba 3f f2 81 77 3f f5 25 7d 3f f7 d0 df 3f fa 83 b3 3f fd 3e 0c 40 00 00 00 }

  condition:
    $a0
}