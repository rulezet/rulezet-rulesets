rule libavcodec_AC3_ff_eac3_gaq_remap_2_4_b__8_byt_18_ {
  strings:
    $a0 = { EA FB D2 EC C8 E6 C4 E3 C2 E1 C1 E0 C0 E0 C0 E0 C0 E0 }

  condition:
    $a0
}