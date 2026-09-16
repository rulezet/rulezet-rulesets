rule libavcodec_real_audio_288_gain_window__flt64___64_lil_304_ {
  strings:
    $a0 = { 5e 47 e7 bf b1 2e e0 3f ec ad e1 1f 3f c6 e0 3f 97 4b 36 60 88 63 e1 3f 46 ec 3e c0 8d 06 e2 3f 98 04 c6 ff bf af e2 3f 1e f3 2a 00 00 5f e3 3f 59 2a c8 ff 7f 14 e4 3f d9 81 24 00 c0 d0 e4 3f e8 a3 dd ff ff 93 e5 3f 44 71 06 00 40 5e e6 3f 98 04 c6 ff bf 2f e7 3f 1b 50 ca ff 3f 09 e8 3f 65 58 d9 ff 7f ea e8 3f e8 a3 dd ff ff d3 e9 3f 0c 2e 11 00 00 c6 ea 3f e2 0c d5 ff ff c0 eb 3f 33 ac ec ff 3f c5 ec 3f 06 97 08 00 00 d3 ed 3f 59 2a c8 ff 7f c4 ee 3f 9e 9b ce ff bf 72 ef 3f 21 e7 d2 ff 3f dc ef 3f 00 00 00 00 00 00 f0 3f d3 ea 1b 00 c0 dd ef 3f 0c 2e 11 00 00 76 ef 3f 1b 50 ca ff 3f c9 ee 3f 1b 50 ca ff 3f d9 ed 3f 30 b8 44 00 00 a8 ec 3f 30 b8 44 00 00 38 eb 3f 89 e2 0c 00 80 8c e9 3f 12 c5 19 00 00 a9 e7 3f 24 8a 33 00 00 92 e5 3f b0 60 e8 ff bf 4b e3 3f 3f da fd ff 3f db e0 3f 47 65 ae ff 7f 8b dc 3f 95 10 1e 00 80 22 d7 3f dc 24 85 00 80 86 d1 3f b3 54 90 ff ff 88 c7 3f c8 20 f9 ff ff a3 b7 3f }

  condition:
    $a0
}