rule LD_CELP_G_728_cb_gain_sq__flt32___32_lil_32_ {
  strings:
    $a0 = { 00 20 88 3e 00 71 50 3f 84 96 1f 40 7a 5e f4 40 00 20 88 3e 00 71 50 3f 84 96 1f 40 7a 5e f4 40 }

  condition:
    $a0
}