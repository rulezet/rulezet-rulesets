rule libavcodec_Chinese_AVS_video__AVS1_P2__JiZhun__dequant_mul__16_big_128_ {
  strings:
    $a0 = { 80 00 8c dd 98 38 a5 ff b5 05 c5 67 d8 8d ec 08 80 a4 8b 96 98 38 a5 ff b4 61 c5 67 d7 45 ea 1d ff ff 8b 96 98 38 a6 51 b5 05 c5 b9 d6 f3 ea c1 80 29 8b 96 98 38 a5 d6 b5 2e c5 90 d7 45 ea 98 ff ff 8b 96 98 38 a5 ff b4 f0 c5 53 d7 45 ea ac ff ff 8b a0 98 38 a5 ff b5 05 c5 67 d7 3b ea b7 ff ff 8b 96 98 3d a6 04 b5 05 c5 67 d7 45 ea c1 80 03 8b 96 98 35 a6 01 b5 05 c5 67 d7 45 ea c3 }

  condition:
    $a0
}