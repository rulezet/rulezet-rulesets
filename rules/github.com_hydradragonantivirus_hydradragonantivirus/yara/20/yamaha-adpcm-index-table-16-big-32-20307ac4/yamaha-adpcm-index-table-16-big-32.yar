rule Yamaha_ADPCM_index_table__16_big_32_ {
  strings:
    $a0 = { 00 e6 00 e6 00 e6 00 e6 01 33 01 99 02 00 02 66 00 e6 00 e6 00 e6 00 e6 01 33 01 99 02 00 02 66 }

  condition:
    $a0
}