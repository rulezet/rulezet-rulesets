rule War_Times_CRC_algorithm__32_big_16_ {
  strings:
    $a0 = { 00 00 16 2e 00 00 04 d0 00 00 19 94 00 00 26 94 }

  condition:
    $a0
}