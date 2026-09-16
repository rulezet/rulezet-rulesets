rule libavcodec_real_audio_144_cb2_base__16_big_256_ {
  strings:
    $a0 = { 2f 8e 34 44 36 37 36 08 33 72 33 ab 33 94 2f 15 30 7a 36 a4 38 0c 39 27 33 2c 34 67 33 a8 2f ec 2e ce 36 01 34 bb 37 82 36 35 39 c4 35 f3 33 35 2c b9 33 db 32 21 35 95 31 b8 35 80 31 d7 30 75 27 f6 2f 99 2d 6c 33 69 2d f2 34 92 30 18 32 12 28 cb 31 e5 2e eb 36 c4 2e 2a 36 01 30 a5 33 aa 28 ce 33 6a 2e 69 37 dc 32 3b 3f a0 34 b2 3a cd 27 ab 32 14 2c ff 36 95 2f 09 3a e9 31 5b 37 76 37 76 31 5b 3a e9 2f 09 36 95 2c ff 32 14 27 ab 3a cd 34 b2 3f a0 32 3b 37 dc 2e 69 33 6a 28 ce 33 aa 30 a5 36 01 2e 2a 36 c4 2e eb 31 e5 28 cb 32 12 30 18 34 92 2d f2 33 69 2d 6c 2f 99 27 f6 30 75 31 d7 35 80 31 b8 35 95 32 21 33 db 2c b9 33 35 35 f3 39 c4 36 35 37 82 34 bb 36 01 2e ce 2f ec 33 a8 34 67 33 2c 39 27 38 0c 36 a4 30 7a 2f 15 33 94 33 ab 33 72 36 08 36 37 34 44 2f 8e }

  condition:
    $a0
}