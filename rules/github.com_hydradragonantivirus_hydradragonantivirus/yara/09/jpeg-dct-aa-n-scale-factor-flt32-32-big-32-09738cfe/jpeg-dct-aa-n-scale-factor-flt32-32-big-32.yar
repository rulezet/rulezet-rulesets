rule Jpeg_dct_AA_N_scale_factor__flt32___32_big_32_ {
  strings:
    $a0 = { 3f 80 00 00 3f b1 8a 86 3f a7 3d 75 3f 96 83 17 3f 80 00 00 3f 49 23 4e 3f 0a 8b d4 3e 8d 42 af }

  condition:
    $a0
}