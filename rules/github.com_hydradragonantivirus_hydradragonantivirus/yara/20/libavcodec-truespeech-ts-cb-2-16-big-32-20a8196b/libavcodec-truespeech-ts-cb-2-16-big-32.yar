rule libavcodec_truespeech_ts_cb_2__16_big_32_ {
  strings:
    $a0 = { 96 f8 a3 b4 af 45 ba 53 c4 b1 ce cc d8 6f e2 1e eb f3 f6 40 00 f7 0c 20 18 81 26 9a 37 6b 4d 60 }

  condition:
    $a0
}