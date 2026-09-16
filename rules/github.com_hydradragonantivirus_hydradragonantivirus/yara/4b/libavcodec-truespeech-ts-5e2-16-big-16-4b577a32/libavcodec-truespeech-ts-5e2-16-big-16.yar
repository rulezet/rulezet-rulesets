rule libavcodec_truespeech_ts_5E2__16_big_16_ {
  strings:
    $a0 = { 46 66 26 b8 15 4c 0b b6 06 71 03 8b 01 f3 01 12 }

  condition:
    $a0
}