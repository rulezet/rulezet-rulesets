rule libavcodec_truespeech_ts_cb_2__16_lil_32_ {
  strings:
    $a0 = { f8 96 b4 a3 45 af 53 ba b1 c4 cc ce 6f d8 1e e2 f3 eb 40 f6 f7 00 20 0c 81 18 9a 26 6b 37 60 4d }

  condition:
    $a0
}