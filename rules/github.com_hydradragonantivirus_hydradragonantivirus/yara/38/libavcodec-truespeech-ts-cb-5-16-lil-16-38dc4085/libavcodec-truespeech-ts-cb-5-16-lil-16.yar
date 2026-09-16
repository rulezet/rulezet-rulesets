rule libavcodec_truespeech_ts_cb_5__16_lil_16_ {
  strings:
    $a0 = { 1b d5 2e f1 2e 04 c7 13 60 22 1b 31 de 40 85 53 }

  condition:
    $a0
}