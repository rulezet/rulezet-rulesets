rule libavcodec_Chinese_AVS_video__AVS1_P2__JiZhun__dequant_mul__16_lil_128_ {
  strings:
    $a0 = { 00 80 dd 8c 38 98 ff a5 05 b5 67 c5 8d d8 08 ec a4 80 96 8b 38 98 ff a5 61 b4 67 c5 45 d7 1d ea ff ff 96 8b 38 98 51 a6 05 b5 b9 c5 f3 d6 c1 ea 29 80 96 8b 38 98 d6 a5 2e b5 90 c5 45 d7 98 ea ff ff 96 8b 38 98 ff a5 f0 b4 53 c5 45 d7 ac ea ff ff a0 8b 38 98 ff a5 05 b5 67 c5 3b d7 b7 ea ff ff 96 8b 3d 98 04 a6 05 b5 67 c5 45 d7 c1 ea 03 80 96 8b 35 98 01 a6 05 b5 67 c5 45 d7 c3 ea }

  condition:
    $a0
}