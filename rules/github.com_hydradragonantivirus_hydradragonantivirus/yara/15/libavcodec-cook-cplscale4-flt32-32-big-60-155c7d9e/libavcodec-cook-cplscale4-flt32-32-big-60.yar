rule libavcodec_COOK_cplscale4__flt32___32_big_60_ {
  strings:
    $a0 = { 3f 7d d2 13 3f 79 26 d9 3f 73 f9 29 3f 6e 1d 3b 3f 67 48 b6 3f 5e e9 39 3f 53 80 90 3f 35 04 f3 3f 10 3b 59 3e fb c4 65 3e db 7c d0 3e bc 04 74 3e 9b 16 6c 3e 6b 44 58 3e 05 55 38 }

  condition:
    $a0
}