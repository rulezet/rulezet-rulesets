rule Yamaha_ADPCM_diff_lookup_table__32_big_64_ {
  strings:
    $a0 = { 00 00 00 01 00 00 00 03 00 00 00 05 00 00 00 07 00 00 00 09 00 00 00 0B 00 00 00 0D 00 00 00 0F FF FF FF FF FF FF FF FD FF FF FF FB FF FF FF F9 FF FF FF F7 FF FF FF F5 FF FF FF F3 FF FF FF F1 }

  condition:
    $a0
}