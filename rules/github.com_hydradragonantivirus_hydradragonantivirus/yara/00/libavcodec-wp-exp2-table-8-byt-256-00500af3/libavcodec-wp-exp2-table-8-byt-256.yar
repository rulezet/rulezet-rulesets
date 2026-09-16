rule libavcodec_wp_exp2_table__8_byt_256_ {
  strings:
    $a0 = { 00 01 01 02 03 03 04 05 06 06 07 08 08 09 0a 0b 0b 0c 0d 0e 0e 0f 10 10 11 12 13 13 14 15 16 16 17 18 19 19 1a 1b 1c 1d 1d 1e 1f 20 20 21 22 23 24 24 25 26 27 28 28 29 2a 2b 2c 2c 2d 2e 2f 30 30 31 32 33 34 35 35 36 37 38 39 3a 3a 3b 3c 3d 3e 3f 40 41 41 42 43 44 45 46 47 48 48 49 4a 4b 4c 4d 4e 4f 50 51 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5e 5f 60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 95 96 97 98 99 9a 9b 9c 9d 9f a0 a1 a2 a3 a4 a5 a6 a8 a9 aa ab ac ad af b0 b1 b2 b3 b4 b6 b7 b8 b9 ba bc bd be bf c0 c2 c3 c4 c5 c6 c8 c9 ca cb cd ce cf d0 d2 d3 d4 d6 d7 d8 d9 db dc dd de e0 e1 e2 e4 e5 e6 e8 e9 ea ec ed ee f0 f1 f2 f4 f5 f6 f8 f9 fa fc fd ff }

  condition:
    $a0
}