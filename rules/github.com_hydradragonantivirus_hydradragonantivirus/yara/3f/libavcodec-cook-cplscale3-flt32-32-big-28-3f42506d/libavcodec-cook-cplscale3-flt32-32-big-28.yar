rule libavcodec_COOK_cplscale3__flt32___32_big_28_ {
  strings:
    $a0 = { 3f 7b 35 27 3f 6f df 13 3f 60 3d 3e 3f 35 04 f3 3e f7 01 12 3e b2 dc 25 3e 45 35 a7 }

  condition:
    $a0
}