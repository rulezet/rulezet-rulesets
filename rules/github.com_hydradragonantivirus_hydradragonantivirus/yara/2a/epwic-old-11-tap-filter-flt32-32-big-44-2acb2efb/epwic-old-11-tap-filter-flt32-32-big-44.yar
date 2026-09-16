rule EPWIC_old_11_tap_filter__flt32___32_big_44_ {
  strings:
    $a0 = { 3c 02 df 1a 3c a4 cb 5b bd 4d 72 0a bd fe 68 ca 3e 95 97 48 3f 35 4d 7d 3e 95 97 48 bd fe 68 ca bd 4d 72 0a 3c a4 cb 5b 3c 02 df 1a }

  condition:
    $a0
}