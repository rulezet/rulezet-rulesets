rule libavcodec_truespeech_ts_cb_6__16_big_16_ {
  strings:
    $a0 = { b5 50 c8 25 d9 80 e9 97 f8 83 07 52 18 11 2e 18 }

  condition:
    $a0
}