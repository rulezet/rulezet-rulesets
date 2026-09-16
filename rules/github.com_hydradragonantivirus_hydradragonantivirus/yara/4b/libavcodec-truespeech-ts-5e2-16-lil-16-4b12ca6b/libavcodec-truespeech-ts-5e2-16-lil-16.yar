rule libavcodec_truespeech_ts_5E2__16_lil_16_ {
  strings:
    $a0 = { 66 46 b8 26 4c 15 b6 0b 71 06 8b 03 f3 01 12 01 }

  condition:
    $a0
}