rule libavcodec_celp_math_tab_log2__16_lil_66_ {
  strings:
    $a0 = { 04 00 b3 05 36 0b 90 10 c4 15 d3 1a bf 1f 8b 24 38 29 c7 2d 3a 32 93 36 d1 3a f8 3e 06 43 ff 46 e2 4a b1 4e 6c 52 14 56 aa 59 2e 5d a2 60 05 64 59 67 9e 6a d4 6d fc 70 17 74 24 77 25 7a 19 7d 01 80 }

  condition:
    $a0
}