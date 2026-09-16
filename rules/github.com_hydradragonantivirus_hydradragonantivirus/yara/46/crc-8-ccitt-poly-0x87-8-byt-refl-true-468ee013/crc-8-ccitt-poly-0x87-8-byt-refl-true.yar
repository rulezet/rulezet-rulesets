rule CRC_8_CCITT_poly_0x87__8_byt_refl_True_ {
  strings:
    $a0 = { 00 2f 5e 71 bc 93 e2 cd bb 94 e5 ca 07 28 59 76 b5 9a eb c4 09 26 57 78 0e 21 50 7f b2 9d ec c3 a9 86 f7 d8 15 3a 4b 64 12 3d 4c 63 ae 81 f0 df 1c 33 42 6d a0 8f fe d1 a7 88 f9 d6 1b 34 45 6a 91 be cf e0 2d 02 73 5c 2a 05 74 5b 96 b9 c8 e7 24 0b 7a 55 98 b7 c6 e9 9f b0 c1 ee 23 0c 7d 52 38 17 66 49 84 ab da f5 83 ac dd f2 3f 10 61 4e 8d a2 d3 fc 31 1e 6f 40 36 19 68 47 8a a5 d4 fb e1 ce bf 90 5d 72 03 2c 5a 75 04 2b e6 c9 b8 97 54 7b 0a 25 e8 c7 b6 99 ef c0 b1 9e 53 7c 0d 22 48 67 16 39 f4 db aa 85 f3 dc ad 82 4f 60 11 3e fd d2 a3 8c 41 6e 1f 30 46 69 18 37 fa d5 a4 8b 70 5f 2e 01 cc e3 92 bd cb e4 95 ba 77 58 29 06 c5 ea 9b b4 79 56 27 08 7e 51 20 0f c2 ed 9c b3 d9 f6 87 a8 65 4a 3b 14 62 4d 3c 13 de f1 80 af 6c 43 32 1d d0 ff 8e a1 d7 f8 89 a6 6b 44 35 1a }

  condition:
    $a0
}