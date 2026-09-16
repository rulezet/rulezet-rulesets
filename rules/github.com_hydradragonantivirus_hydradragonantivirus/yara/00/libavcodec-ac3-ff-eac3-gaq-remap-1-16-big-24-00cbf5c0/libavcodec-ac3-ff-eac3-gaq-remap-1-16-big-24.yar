rule libavcodec_AC3_ff_eac3_gaq_remap_1__16_big_24_ {
  strings:
    $a0 = { 12 49 08 89 04 21 02 08 01 02 00 81 00 40 00 20 00 10 00 08 00 02 00 00 }

  condition:
    $a0
}