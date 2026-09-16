rule libavcodec_atrac_qmf_48tap_half__flt64___64_big_192_ {
  strings:
    $a0 = { be ee a8 8d ae 79 01 a3 bf 18 21 b1 3f fd 6a d5 bf 0d 71 57 60 d3 37 6a 3f 33 bc d6 da 9f a2 b8 3f 2f c0 9f f9 cd 39 6e bf 4b f2 f8 7d a6 2e 33 bf 41 0e c0 81 1c c7 a2 3f 60 a9 a4 82 14 92 95 3f 49 ab 1f 80 04 66 7c bf 71 44 27 1d e7 76 bb bf 48 c7 0b 80 b3 61 f6 3f 80 0e 92 80 4f e5 7e bf 10 09 0b 42 09 5e de bf 8b 87 47 b2 71 2b e7 3f 64 2c 9e 62 8e e7 fb 3f 96 41 fc 3d 97 7e fc bf 7f f4 a5 1c c9 53 34 bf a1 74 46 00 9d e8 3b 3f 93 42 cb 81 9e 25 45 3f ab d0 9e 5f f4 53 c7 bf a6 52 43 bc 0e db dd bf b9 71 40 fd ff a8 4a 3f c0 e7 f7 b6 04 89 52 3f dd b6 22 5b 9f 8d fa }

  condition:
    $a0
}