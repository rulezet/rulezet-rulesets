rule EPWIC_Sum_to_1_hi_filter__flt32___32_lil_36_ {
  strings:
    $a0 = { 8e 9b a2 3c 1a 80 30 3d 72 88 54 bd 66 22 96 be f2 54 10 3f 66 22 96 be 72 88 54 bd 1a 80 30 3d 8e 9b a2 3c }

  condition:
    $a0
}