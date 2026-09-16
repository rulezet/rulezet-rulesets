rule libavcodec_celp_math_tab_exp2_G729_BITEXACT__16_big_66_ {
  strings:
    $a0 = { 40 00 41 67 42 d5 44 4c 45 cb 47 52 48 e2 4a 7a 4c 1c 4d c7 4f 7b 51 38 52 ff 54 d1 56 ac 58 92 5a 82 5c 7e 5e 84 60 96 62 b4 64 dd 67 12 69 54 6b a2 6d fe 70 66 72 dd 75 60 77 f2 7a 93 7d 42 7f ff }

  condition:
    $a0
}