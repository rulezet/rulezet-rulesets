rule CRC_7_poly_0x11__8_byt_refl_True_ {
  strings:
    $a0 = { 00 10 20 30 40 50 60 70 80 90 a0 b0 c0 d0 e0 f0 11 01 31 21 51 41 71 61 91 81 b1 a1 d1 c1 f1 e1 22 32 02 12 62 72 42 52 a2 b2 82 92 e2 f2 c2 d2 33 23 13 03 73 63 53 43 b3 a3 93 83 f3 e3 d3 c3 44 54 64 74 04 14 24 34 c4 d4 e4 f4 84 94 a4 b4 55 45 75 65 15 05 35 25 d5 c5 f5 e5 95 85 b5 a5 66 76 46 56 26 36 06 16 e6 f6 c6 d6 a6 b6 86 96 77 67 57 47 37 27 17 07 f7 e7 d7 c7 b7 a7 97 87 88 98 a8 b8 c8 d8 e8 f8 08 18 28 38 48 58 68 78 99 89 b9 a9 d9 c9 f9 e9 19 09 39 29 59 49 79 69 aa ba 8a 9a ea fa ca da 2a 3a 0a 1a 6a 7a 4a 5a bb ab 9b 8b fb eb db cb 3b 2b 1b 0b 7b 6b 5b 4b cc dc ec fc 8c 9c ac bc 4c 5c 6c 7c 0c 1c 2c 3c dd cd fd ed 9d 8d bd ad 5d 4d 7d 6d 1d 0d 3d 2d ee fe ce de ae be 8e 9e 6e 7e 4e 5e 2e 3e 0e 1e ff ef df cf bf af 9f 8f 7f 6f 5f 4f 3f 2f 1f 0f }

  condition:
    $a0
}