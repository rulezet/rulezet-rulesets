rule libavcodec_dpcm_sol_table_new__8_byt_16_ {
  strings:
    $a0 = { 00 01 02 03 06 0A 0F 15 00 FF FE FD FA F6 F1 EB }

  condition:
    $a0
}