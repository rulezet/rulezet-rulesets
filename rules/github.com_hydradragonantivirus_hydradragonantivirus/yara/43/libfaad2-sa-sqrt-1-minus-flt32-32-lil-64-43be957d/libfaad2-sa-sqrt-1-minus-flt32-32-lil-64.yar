rule libfaad2_sa_sqrt_1_minus__flt32___32_lil_64_ {
  strings:
    $a0 = { 00 00 80 3f 00 00 80 3f b3 ad 7f 3f cb eb 7b 3f 78 5c 7f 3f 09 a0 75 3f c8 ba 7e 3f ff 09 65 3f 7f 7b 7d 3f e7 b1 53 3f c9 0c 7b 3f e8 d0 34 3f 10 66 76 3f e3 25 e8 3e a2 d7 6d 3f 00 00 00 00 }

  condition:
    $a0
}