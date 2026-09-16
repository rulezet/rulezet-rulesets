rule libavcodec_truespeech_ts_cb_0__16_big_64_ {
  strings:
    $a0 = { 82 40 83 64 84 ce 86 5d 88 05 89 de 8b d7 8d f4 90 51 92 e2 95 de 99 0f 9c 81 a0 79 a5 4c aa d2 b1 8a b9 0a c1 24 c9 cc d3 39 dd d3 e9 d6 f8 93 09 6f 1a ca 29 ec 38 1f 45 f9 54 6a 63 c3 73 b5 }

  condition:
    $a0
}