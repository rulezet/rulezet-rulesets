rule libfaad2_pan_pow_2_30_neg__flt32___32_lil_160_ {
  strings:
    $a0 = { 00 00 80 3f 00 00 80 3f 00 00 80 3f 00 00 80 3f 00 00 80 3f f9 04 7f 3f f9 04 7f 3f e8 0a 7e 3f e8 0a 7e 3f e8 0a 7e 3f e8 0a 7e 3f e8 0a 7e 3f a5 19 7c 3f 71 22 7b 3f 71 22 7b 3f cd 11 7d 3f a5 19 7c 3f 30 2c 7a 3f 10 4f 77 3f 8f 5c 76 3f a5 19 7c 3f 30 2c 7a 3f 10 4f 77 3f 9a 8a 73 3f 0a ae 71 3f 71 22 7b 3f 80 42 78 3f 9a 8a 73 3f ce e9 6e 3f ad 2d 6c 3f 30 2c 7a 3f fb 6a 75 3f fa d4 6f 3f 62 5f 6a 3f 0d eb 65 3f 80 42 78 3f f0 9b 72 3f ad 2d 6c 3f 0d eb 65 3f e8 d2 5f 3f }

  condition:
    $a0
}