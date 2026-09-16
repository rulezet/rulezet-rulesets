rule libavcodec_truespeech_ts_240__16_big_100_ {
  strings:
    $a0 = { ed 2f 52 39 54 f1 e4 a9 26 20 ee 3e 09 d6 2c 40 ef b5 2b e0 3f e1 33 39 44 2f e6 fe 44 58 f9 df f2 31 43 db 3d b0 f7 05 4f 7b fe fb 26 ad 0c dc 33 c2 07 39 12 be 43 a2 1b df 1f 3e 02 11 07 96 2a eb 16 3f 05 0d 3a 38 0d 1e 0d 78 15 0f 33 46 38 a4 0b 7d 2d 5d 1f df 19 b7 28 22 0d 99 1f 12 19 4c 0c e6 }

  condition:
    $a0
}