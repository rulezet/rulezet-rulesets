rule libavcodec_dpcm_sol_table_old__32_big_64_ {
  strings:
    $a0 = { 00 00 00 00 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00 06 00 00 00 0A 00 00 00 0F 00 00 00 15 FF FF FF EB FF FF FF F1 FF FF FF F6 FF FF FF FA FF FF FF FD FF FF FF FE FF FF FF FF 00 00 00 00 }

  condition:
    $a0
}