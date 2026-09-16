rule libfaad2_pan_pow_2_30_pos__flt64___64_big_320_ {
  strings:
    $a0 = { 3f f0 00 00 00 00 00 00 3f f0 00 00 00 00 00 00 3f f0 00 00 00 00 00 00 3f f0 00 00 00 00 00 00 3f f0 00 00 00 00 00 00 3f f0 0f bf e0 a2 8f 03 3f f0 0f bf e0 a2 8f 03 3f f0 1f 8f 42 5b 4c e0 3f f0 1f 8f 42 5b 4c e0 3f f0 1f 8f 42 5b 4c e0 3f f0 1f 8f 42 5b 4c e0 3f f0 1f 8f 42 5b 4c e0 3f f0 3f 5c c4 a7 0e 77 3f f0 4f 5b 04 18 cf 96 3f f0 4f 5b 04 18 cf 96 3f f0 2f 6e 33 a9 13 a4 3f f0 3f 5c c4 a7 0e 77 3f f0 5f 69 01 d4 c9 fa 3f f0 8f f2 0b 64 7b ef 3f f0 a0 3f 9d 2c 7e c2 3f f0 3f 5c c4 a7 0e 77 3f f0 5f 69 01 d4 c9 fa 3f f0 8f f2 0b 64 7b ef 3f f0 d1 88 db 7d b7 07 3f f0 f2 b2 da 29 ce fe 3f f0 4f 5b 04 18 cf 96 3f f0 7f b4 75 e8 e5 5c 3f f0 d1 88 db 7d b7 07 3f f1 24 f0 82 e8 04 ea 3f f1 57 c3 1a 9c 63 78 3f f0 5f 69 01 d4 c9 fa 3f f0 b0 9d 3b 5c 18 fd 3f f1 14 20 d3 c6 4c 66 3f f1 79 f8 6d 06 0a 28 3f f1 d0 a6 11 bb d8 f8 3f f0 7f b4 75 e8 e5 5c 3f f0 e2 14 6e ef 43 67 3f f1 57 c3 1a 9c 63 78 3f f1 d0 a6 11 bb d8 f8 3f f2 4c d3 a9 fa 7e a6 }

  condition:
    $a0
}