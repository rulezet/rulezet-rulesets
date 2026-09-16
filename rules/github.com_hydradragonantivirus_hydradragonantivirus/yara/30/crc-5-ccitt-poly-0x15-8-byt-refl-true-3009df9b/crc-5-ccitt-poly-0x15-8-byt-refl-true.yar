rule CRC_5_CCITT_poly_0x15__8_byt_refl_True_ {
  strings:
    $a0 = { 00 40 80 c0 51 11 d1 91 a2 e2 22 62 f3 b3 73 33 15 55 95 d5 44 04 c4 84 b7 f7 37 77 e6 a6 66 26 2a 6a aa ea 7b 3b fb bb 88 c8 08 48 d9 99 59 19 3f 7f bf ff 6e 2e ee ae 9d dd 1d 5d cc 8c 4c 0c 54 14 d4 94 05 45 85 c5 f6 b6 76 36 a7 e7 27 67 41 01 c1 81 10 50 90 d0 e3 a3 63 23 b2 f2 32 72 7e 3e fe be 2f 6f af ef dc 9c 5c 1c 8d cd 0d 4d 6b 2b eb ab 3a 7a ba fa c9 89 49 09 98 d8 18 58 a8 e8 28 68 f9 b9 79 39 0a 4a 8a ca 5b 1b db 9b bd fd 3d 7d ec ac 6c 2c 1f 5f 9f df 4e 0e ce 8e 82 c2 02 42 d3 93 53 13 20 60 a0 e0 71 31 f1 b1 97 d7 17 57 c6 86 46 06 35 75 b5 f5 64 24 e4 a4 fc bc 7c 3c ad ed 2d 6d 5e 1e de 9e 0f 4f 8f cf e9 a9 69 29 b8 f8 38 78 4b 0b cb 8b 1a 5a 9a da d6 96 56 16 87 c7 07 47 74 34 f4 b4 25 65 a5 e5 c3 83 43 03 92 d2 12 52 61 21 e1 a1 30 70 b0 f0 }

  condition:
    $a0
}