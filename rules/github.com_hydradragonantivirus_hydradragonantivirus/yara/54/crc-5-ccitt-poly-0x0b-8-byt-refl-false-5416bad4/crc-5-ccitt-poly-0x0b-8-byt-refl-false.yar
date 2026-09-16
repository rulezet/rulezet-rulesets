rule CRC_5_CCITT_poly_0x0b__8_byt_refl_False_ {
  strings:
    $a0 = { 00 0b 16 1d 2c 27 3a 31 58 53 4e 45 74 7f 62 69 b0 bb a6 ad 9c 97 8a 81 e8 e3 fe f5 c4 cf d2 d9 6b 60 7d 76 47 4c 51 5a 33 38 25 2e 1f 14 09 02 db d0 cd c6 f7 fc e1 ea 83 88 95 9e af a4 b9 b2 d6 dd c0 cb fa f1 ec e7 8e 85 98 93 a2 a9 b4 bf 66 6d 70 7b 4a 41 5c 57 3e 35 28 23 12 19 04 0f bd b6 ab a0 91 9a 87 8c e5 ee f3 f8 c9 c2 df d4 0d 06 1b 10 21 2a 37 3c 55 5e 43 48 79 72 6f 64 a7 ac b1 ba 8b 80 9d 96 ff f4 e9 e2 d3 d8 c5 ce 17 1c 01 0a 3b 30 2d 26 4f 44 59 52 63 68 75 7e cc c7 da d1 e0 eb f6 fd 94 9f 82 89 b8 b3 ae a5 7c 77 6a 61 50 5b 46 4d 24 2f 32 39 08 03 1e 15 71 7a 67 6c 5d 56 4b 40 29 22 3f 34 05 0e 13 18 c1 ca d7 dc ed e6 fb f0 99 92 8f 84 b5 be a3 a8 1a 11 0c 07 36 3d 20 2b 42 49 54 5f 6e 65 78 73 aa a1 bc b7 86 8d 90 9b f2 f9 e4 ef de d5 c8 c3 }

  condition:
    $a0
}