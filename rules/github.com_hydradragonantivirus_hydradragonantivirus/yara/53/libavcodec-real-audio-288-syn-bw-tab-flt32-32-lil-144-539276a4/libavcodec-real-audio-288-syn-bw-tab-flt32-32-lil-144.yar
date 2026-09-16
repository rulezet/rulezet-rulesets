rule libavcodec_real_audio_288_syn_bw_tab__flt32___32_lil_144_ {
  strings:
    $a0 = { 00 00 7d 3f 00 09 7a 3f e5 1a 77 3f 94 35 74 3f f3 58 71 3f e8 84 6e 3f 59 b9 6b 3f 2d f6 68 3f 4a 3b 66 3f 98 88 63 3f fe dd 60 3f 64 3b 5e 3f b2 a0 5b 3f d0 0d 59 3f a7 82 56 3f 1f ff 53 3f 22 83 51 3f 99 0e 4f 3f 6d a1 4c 3f 89 3b 4a 3f d6 dc 47 3f 3f 85 45 3f af 34 43 3f 11 eb 40 3f 50 a8 3e 3f 57 6c 3c 3f 12 37 3a 3f 6d 08 38 3f 54 e0 35 3f b3 be 33 3f 77 a3 31 3f 8d 8e 2f 3f e1 7f 2d 3f 61 77 2b 3f fb 74 29 3f 9c 78 27 3f }

  condition:
    $a0
}