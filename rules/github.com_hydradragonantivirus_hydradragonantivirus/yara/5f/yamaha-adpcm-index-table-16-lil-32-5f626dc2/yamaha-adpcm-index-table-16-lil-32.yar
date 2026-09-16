rule Yamaha_ADPCM_index_table__16_lil_32_ {
  strings:
    $a0 = { e6 00 e6 00 e6 00 e6 00 33 01 99 01 00 02 66 02 e6 00 e6 00 e6 00 e6 00 33 01 99 01 00 02 66 02 }

  condition:
    $a0
}