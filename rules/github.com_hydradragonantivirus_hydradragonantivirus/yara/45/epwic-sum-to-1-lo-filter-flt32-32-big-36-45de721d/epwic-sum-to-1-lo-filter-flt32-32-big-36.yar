rule EPWIC_Sum_to_1_lo_filter__flt32___32_big_36_ {
  strings:
    $a0 = { 3c a2 9b 8e bd 30 80 1a bd 54 88 72 3e 96 22 66 3f 10 54 f2 3e 96 22 66 bd 54 88 72 bd 30 80 1a 3c a2 9b 8e }

  condition:
    $a0
}