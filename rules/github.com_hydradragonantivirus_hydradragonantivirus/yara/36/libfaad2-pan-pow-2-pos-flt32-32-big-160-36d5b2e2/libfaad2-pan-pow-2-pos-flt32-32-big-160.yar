rule libfaad2_pan_pow_2_pos__flt32___32_big_160_ {
  strings:
    $a0 = { 3f 80 00 00 3f 80 00 00 3f 80 00 00 3f 80 00 00 3f 80 00 00 3f 8f 9d c4 3f 8f 9d c4 3f a1 24 a8 3f a1 24 a8 3f a1 24 a8 3f a1 24 a8 3f a1 24 a8 3f ca de 4c 3f e3 9f 63 3f e3 9f 63 3f b4 ce 60 3f ca de 4c 3f ff 65 bb 40 34 61 6c 40 4a 64 0d 3f ca de 4c 3f ff 65 bc 40 34 61 6c 40 8e f1 81 40 b3 f1 88 3f e3 9f 63 40 20 c3 91 40 8e f1 81 40 fe 2d c7 41 33 85 18 3f ff 65 bb 40 63 16 38 40 e2 89 5b 41 62 00 d8 41 c8 f3 75 40 20 c3 91 40 a0 5f d8 41 33 85 18 41 c8 f3 75 42 60 f0 c9 }

  condition:
    $a0
}