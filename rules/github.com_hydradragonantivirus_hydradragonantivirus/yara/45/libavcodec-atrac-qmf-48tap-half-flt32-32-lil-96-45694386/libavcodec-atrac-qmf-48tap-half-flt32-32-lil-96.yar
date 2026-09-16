rule libavcodec_atrac_qmf_48tap_half__flt32___32_lil_96_ {
  strings:
    $a0 = { 6d 44 75 b7 8a 0d c1 b8 bb 8a 6b b8 b7 e6 9d 39 00 05 7e 39 c4 97 5f ba 04 76 08 ba 24 4d 05 3b fc 58 4d 3a 39 21 8a bb 5c 38 46 ba 94 74 00 3c 5a 48 80 b8 3e 3a 5c bc f3 64 21 3b e2 0f b2 3c 29 a5 ff bb 30 a2 0b bd 5c 16 9a 3c f3 84 5e 3d 1e 92 32 bd 08 8a cb bd be 3f 07 3e 13 b1 ed 3e }

  condition:
    $a0
}