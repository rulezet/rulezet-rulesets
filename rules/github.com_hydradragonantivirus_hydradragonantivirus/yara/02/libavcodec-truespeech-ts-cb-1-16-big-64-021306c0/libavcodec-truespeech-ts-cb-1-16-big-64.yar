rule libavcodec_truespeech_ts_cb_1__16_big_64_ {
  strings:
    $a0 = { 9f 65 b5 6b c5 83 d3 71 e0 18 eb b4 f6 1c ff 59 08 5b 11 06 19 52 21 4a 28 c9 2f f8 36 e6 3d 92 43 df 49 bb 4f 46 54 67 59 30 5d a3 61 ec 65 f9 69 d4 6d 5a 70 9e 73 ad 76 6b 78 f0 7b 5a 7d a5 }

  condition:
    $a0
}