rule libavcodec_ff_nelly_init_table__16_lil_128_ {
  strings:
    $a0 = { 3e 0c de 14 d6 1a 70 1e 79 21 e1 23 10 26 cf 27 87 29 35 2b aa 2c fa 2d 54 2f e1 30 7d 32 f4 33 6a 35 cb 36 10 38 7c 39 0d 3b 75 3c d0 3d 1d 3f 81 40 a4 41 c2 42 f9 43 0f 45 1c 46 3e 47 58 48 4c 49 86 4a b5 4b b8 4c d1 4d ed 4e 14 50 4d 51 aa 52 d9 53 22 55 79 56 b5 57 e4 58 1b 5a 36 5b 54 5c 76 5d a3 5e c9 5f f3 60 13 62 46 63 82 64 08 66 81 67 0f 69 d0 6a e5 6c 2f 6f f2 72 7b 7a }

  condition:
    $a0
}