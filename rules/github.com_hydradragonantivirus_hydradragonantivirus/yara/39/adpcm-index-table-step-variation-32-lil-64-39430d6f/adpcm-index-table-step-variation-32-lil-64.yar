rule ADPCM_index_table__step_variation___32_lil_64_ {
  strings:
    $a0 = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 02 00 00 00 04 00 00 00 06 00 00 00 08 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 02 00 00 00 04 00 00 00 06 00 00 00 08 00 00 00 }

  condition:
    $a0
}