rule libfaad2_pan_pow_2_30_pos__flt32___32_lil_160_ {
  strings:
    $a0 = { 00 00 80 3f 00 00 80 3f 00 00 80 3f 00 00 80 3f 00 00 80 3f ff 7d 80 3f ff 7d 80 3f 7a fc 80 3f 7a fc 80 3f 7a fc 80 3f 7a fc 80 3f 7a fc 80 3f e6 fa 81 3f d8 7a 82 3f d8 7a 82 3f 72 7b 81 3f e6 fa 81 3f 48 fb 82 3f 90 7f 84 3f fd 01 85 3f e6 fa 81 3f 48 fb 82 3f 90 7f 84 3f 47 8c 86 3f 97 95 87 3f d8 7a 82 3f a4 fd 83 3f 47 8c 86 3f 84 27 89 3f 19 be 8a 3f 48 fb 82 3f ea 84 85 3f 07 a1 88 3f c3 cf 8b 3f 31 85 8e 3f a4 fd 83 3f a3 10 87 3f 19 be 8a 3f 31 85 8e 3f 9d 66 92 3f }

  condition:
    $a0
}