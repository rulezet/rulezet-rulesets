rule libavcodec_truespeech_ts_230__16_lil_16_ {
  strings:
    $a0 = { 3b 7f 78 7e b6 7d f5 7c 35 7c 76 7b b8 7a fc 79 }

  condition:
    $a0
}