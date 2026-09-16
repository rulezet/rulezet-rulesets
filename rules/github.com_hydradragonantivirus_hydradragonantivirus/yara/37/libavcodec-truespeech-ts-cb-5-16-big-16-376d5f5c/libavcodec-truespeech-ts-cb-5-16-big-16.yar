rule libavcodec_truespeech_ts_cb_5__16_big_16_ {
  strings:
    $a0 = { d5 1b f1 2e 04 2e 13 c7 22 60 31 1b 40 de 53 85 }

  condition:
    $a0
}