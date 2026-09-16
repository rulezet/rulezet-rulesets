rule CRC_8_CCITT_poly_0x87__8_byt_refl_False_ {
  strings:
    $a0 = { 00 87 89 0e 95 12 1c 9b ad 2a 24 a3 38 bf b1 36 dd 5a 54 d3 48 cf c1 46 70 f7 f9 7e e5 62 6c eb 3d ba b4 33 a8 2f 21 a6 90 17 19 9e 05 82 8c 0b e0 67 69 ee 75 f2 fc 7b 4d ca c4 43 d8 5f 51 d6 7a fd f3 74 ef 68 66 e1 d7 50 5e d9 42 c5 cb 4c a7 20 2e a9 32 b5 bb 3c 0a 8d 83 04 9f 18 16 91 47 c0 ce 49 d2 55 5b dc ea 6d 63 e4 7f f8 f6 71 9a 1d 13 94 0f 88 86 01 37 b0 be 39 a2 25 2b ac f4 73 7d fa 61 e6 e8 6f 59 de d0 57 cc 4b 45 c2 29 ae a0 27 bc 3b 35 b2 84 03 0d 8a 11 96 98 1f c9 4e 40 c7 5c db d5 52 64 e3 ed 6a f1 76 78 ff 14 93 9d 1a 81 06 08 8f b9 3e 30 b7 2c ab a5 22 8e 09 07 80 1b 9c 92 15 23 a4 aa 2d b6 31 3f b8 53 d4 da 5d c6 41 4f c8 fe 79 77 f0 6b ec e2 65 b3 34 3a bd 26 a1 af 28 1e 99 97 10 8b 0c 02 85 6e e9 e7 60 fb 7c 72 f5 c3 44 4a cd 56 d1 df 58 }

  condition:
    $a0
}