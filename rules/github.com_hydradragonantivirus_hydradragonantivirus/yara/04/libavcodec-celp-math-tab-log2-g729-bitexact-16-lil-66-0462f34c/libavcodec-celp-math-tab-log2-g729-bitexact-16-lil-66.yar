rule libavcodec_celp_math_tab_log2_G729_BITEXACT__16_lil_66_ {
  strings:
    $a0 = { 00 00 af 05 32 0b 8c 10 c0 15 cf 1a bc 1f 88 24 35 29 c4 2d 37 32 8f 36 ce 3a f5 3e 04 43 fc 46 df 4a ae 4e 69 52 11 56 a7 59 2c 5d 9f 60 03 64 57 67 9b 6a d1 6d fa 70 14 74 21 77 22 7a 17 7d ff 7f }

  condition:
    $a0
}