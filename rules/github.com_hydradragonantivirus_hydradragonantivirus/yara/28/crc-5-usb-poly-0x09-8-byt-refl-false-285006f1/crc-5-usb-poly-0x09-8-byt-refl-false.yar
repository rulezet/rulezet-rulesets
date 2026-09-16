rule CRC_5_USB_poly_0x09__8_byt_refl_False_ {
  strings:
    $a0 = { 00 09 12 1b 24 2d 36 3f 48 41 5a 53 6c 65 7e 77 90 99 82 8b b4 bd a6 af d8 d1 ca c3 fc f5 ee e7 29 20 3b 32 0d 04 1f 16 61 68 73 7a 45 4c 57 5e b9 b0 ab a2 9d 94 8f 86 f1 f8 e3 ea d5 dc c7 ce 52 5b 40 49 76 7f 64 6d 1a 13 08 01 3e 37 2c 25 c2 cb d0 d9 e6 ef f4 fd 8a 83 98 91 ae a7 bc b5 7b 72 69 60 5f 56 4d 44 33 3a 21 28 17 1e 05 0c eb e2 f9 f0 cf c6 dd d4 a3 aa b1 b8 87 8e 95 9c a4 ad b6 bf 80 89 92 9b ec e5 fe f7 c8 c1 da d3 34 3d 26 2f 10 19 02 0b 7c 75 6e 67 58 51 4a 43 8d 84 9f 96 a9 a0 bb b2 c5 cc d7 de e1 e8 f3 fa 1d 14 0f 06 39 30 2b 22 55 5c 47 4e 71 78 63 6a f6 ff e4 ed d2 db c0 c9 be b7 ac a5 9a 93 88 81 66 6f 74 7d 42 4b 50 59 2e 27 3c 35 0a 03 18 11 df d6 cd c4 fb f2 e9 e0 97 9e 85 8c b3 ba a1 a8 4f 46 5d 54 6b 62 79 70 07 0e 15 1c 23 2a 31 38 }

  condition:
    $a0
}