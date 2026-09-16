rule EPWIC_15_tap_lo_filter__flt32___32_lil_60_ {
  strings:
    $a0 = { e5 83 a3 ba ad 84 23 bb 45 0c 0f 3c df 7e a3 3c 7f f7 4e bd 6d e3 f6 bd 12 0a 96 3e f6 c7 34 3f 12 0a 96 3e 6d e3 f6 bd 7f f7 4e bd df 7e a3 3c 45 0c 0f 3c ad 84 23 bb e5 83 a3 ba }

  condition:
    $a0
}