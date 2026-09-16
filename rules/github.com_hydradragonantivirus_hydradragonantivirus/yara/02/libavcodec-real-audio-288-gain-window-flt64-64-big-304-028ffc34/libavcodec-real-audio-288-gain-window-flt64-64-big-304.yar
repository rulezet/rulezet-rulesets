rule libavcodec_real_audio_288_gain_window__flt64___64_big_304_ {
  strings:
    $a0 = { 3f e0 2e b1 bf e7 47 5e 3f e0 c6 3f 1f e1 ad ec 3f e1 63 88 60 36 4b 97 3f e2 06 8d c0 3e ec 46 3f e2 af bf ff c6 04 98 3f e3 5f 00 00 2a f3 1e 3f e4 14 7f ff c8 2a 59 3f e4 d0 c0 00 24 81 d9 3f e5 93 ff ff dd a3 e8 3f e6 5e 40 00 06 71 44 3f e7 2f bf ff c6 04 98 3f e8 09 3f ff ca 50 1b 3f e8 ea 7f ff d9 58 65 3f e9 d3 ff ff dd a3 e8 3f ea c6 00 00 11 2e 0c 3f eb c0 ff ff d5 0c e2 3f ec c5 3f ff ec ac 33 3f ed d3 00 00 08 97 06 3f ee c4 7f ff c8 2a 59 3f ef 72 bf ff ce 9b 9e 3f ef dc 3f ff d2 e7 21 3f f0 00 00 00 00 00 00 3f ef dd c0 00 1b ea d3 3f ef 76 00 00 11 2e 0c 3f ee c9 3f ff ca 50 1b 3f ed d9 3f ff ca 50 1b 3f ec a8 00 00 44 b8 30 3f eb 38 00 00 44 b8 30 3f e9 8c 80 00 0c e2 89 3f e7 a9 00 00 19 c5 12 3f e5 92 00 00 33 8a 24 3f e3 4b bf ff e8 60 b0 3f e0 db 3f ff fd da 3f 3f dc 8b 7f ff ae 65 47 3f d7 22 80 00 1e 10 95 3f d1 86 80 00 85 24 dc 3f c7 88 ff ff 90 54 b3 3f b7 a3 ff ff f9 20 c8 }

  condition:
    $a0
}