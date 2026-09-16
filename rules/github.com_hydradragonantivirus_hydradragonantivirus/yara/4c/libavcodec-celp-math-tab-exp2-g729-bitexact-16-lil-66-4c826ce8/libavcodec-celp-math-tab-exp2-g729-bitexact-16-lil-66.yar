rule libavcodec_celp_math_tab_exp2_G729_BITEXACT__16_lil_66_ {
  strings:
    $a0 = { 00 40 67 41 d5 42 4c 44 cb 45 52 47 e2 48 7a 4a 1c 4c c7 4d 7b 4f 38 51 ff 52 d1 54 ac 56 92 58 82 5a 7e 5c 84 5e 96 60 b4 62 dd 64 12 67 54 69 a2 6b fe 6d 66 70 dd 72 60 75 f2 77 93 7a 42 7d ff 7f }

  condition:
    $a0
}