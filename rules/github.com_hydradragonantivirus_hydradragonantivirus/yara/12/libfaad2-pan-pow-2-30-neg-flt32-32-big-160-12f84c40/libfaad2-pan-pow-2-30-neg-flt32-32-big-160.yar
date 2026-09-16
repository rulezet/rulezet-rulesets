rule libfaad2_pan_pow_2_30_neg__flt32___32_big_160_ {
  strings:
    $a0 = { 3f 80 00 00 3f 80 00 00 3f 80 00 00 3f 80 00 00 3f 80 00 00 3f 7f 04 f9 3f 7f 04 f9 3f 7e 0a e8 3f 7e 0a e8 3f 7e 0a e8 3f 7e 0a e8 3f 7e 0a e8 3f 7c 19 a5 3f 7b 22 71 3f 7b 22 71 3f 7d 11 cd 3f 7c 19 a5 3f 7a 2c 30 3f 77 4f 10 3f 76 5c 8f 3f 7c 19 a5 3f 7a 2c 30 3f 77 4f 10 3f 73 8a 9a 3f 71 ae 0a 3f 7b 22 71 3f 78 42 80 3f 73 8a 9a 3f 6e e9 ce 3f 6c 2d ad 3f 7a 2c 30 3f 75 6a fb 3f 6f d4 fa 3f 6a 5f 62 3f 65 eb 0d 3f 78 42 80 3f 72 9b f0 3f 6c 2d ad 3f 65 eb 0d 3f 5f d2 e8 }

  condition:
    $a0
}