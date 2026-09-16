rule libavcodec_truespeech_ts_cb_1__16_lil_64_ {
  strings:
    $a0 = { 65 9f 6b b5 83 c5 71 d3 18 e0 b4 eb 1c f6 59 ff 5b 08 06 11 52 19 4a 21 c9 28 f8 2f e6 36 92 3d df 43 bb 49 46 4f 67 54 30 59 a3 5d ec 61 f9 65 d4 69 5a 6d 9e 70 ad 73 6b 76 f0 78 5a 7b a5 7d }

  condition:
    $a0
}