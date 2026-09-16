rule EPWIC_old_15_tap_filter__flt32___32_lil_60_ {
  strings:
    $a0 = { c1 b9 a0 ba 5c 16 71 bb 17 a2 0c 3c 06 c7 aa 3c b3 f2 4d bd 16 92 f8 bd 00 fa 95 3e 42 5a 35 3f 00 fa 95 3e 16 92 f8 bd b3 f2 4d bd 06 c7 aa 3c 17 a2 0c 3c 5c 16 71 bb c1 b9 a0 ba }

  condition:
    $a0
}