rule libavcodec_ff_nelly_init_table__16_big_128_ {
  strings:
    $a0 = { 0c 3e 14 de 1a d6 1e 70 21 79 23 e1 26 10 27 cf 29 87 2b 35 2c aa 2d fa 2f 54 30 e1 32 7d 33 f4 35 6a 36 cb 38 10 39 7c 3b 0d 3c 75 3d d0 3f 1d 40 81 41 a4 42 c2 43 f9 45 0f 46 1c 47 3e 48 58 49 4c 4a 86 4b b5 4c b8 4d d1 4e ed 50 14 51 4d 52 aa 53 d9 55 22 56 79 57 b5 58 e4 5a 1b 5b 36 5c 54 5d 76 5e a3 5f c9 60 f3 62 13 63 46 64 82 66 08 67 81 69 0f 6a d0 6c e5 6f 2f 72 f2 7a 7b }

  condition:
    $a0
}