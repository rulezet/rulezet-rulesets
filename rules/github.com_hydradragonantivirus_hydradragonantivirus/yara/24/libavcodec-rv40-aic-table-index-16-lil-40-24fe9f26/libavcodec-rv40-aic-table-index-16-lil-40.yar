rule libavcodec_rv40_aic_table_index__16_lil_40_ {
  strings:
    $a0 = { 00 00 00 01 00 02 11 00 11 01 11 02 11 05 11 06 22 00 22 01 22 02 22 07 72 02 27 02 22 08 82 02 28 02 12 01 16 01 21 02 }

  condition:
    $a0
}