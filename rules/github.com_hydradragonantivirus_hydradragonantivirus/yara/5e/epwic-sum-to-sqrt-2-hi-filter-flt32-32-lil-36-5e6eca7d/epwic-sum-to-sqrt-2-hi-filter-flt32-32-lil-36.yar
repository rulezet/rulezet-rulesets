rule EPWIC_Sum_to_sqrt_2_hi_filter__flt32___32_lil_36_ {
  strings:
    $a0 = { 41 f6 e5 3c f8 9b 79 3d 95 48 96 bd 73 52 d4 be b3 1d 4c 3f 73 52 d4 be 95 48 96 bd f8 9b 79 3d 41 f6 e5 3c }

  condition:
    $a0
}