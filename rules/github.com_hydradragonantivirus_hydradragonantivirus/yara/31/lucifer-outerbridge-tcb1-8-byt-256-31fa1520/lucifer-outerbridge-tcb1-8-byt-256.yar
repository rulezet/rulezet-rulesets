rule Lucifer__outerbridge__TCB1__8_byt_256_ {
  strings:
    $a0 = { 57 df cf d3 d7 5f db 43 c3 c7 cb 4b 5b 47 4f 53 15 9d 8d 91 95 1d 99 01 81 85 89 09 19 05 0d 11 75 fd ed f1 f5 7d f9 61 e1 e5 e9 69 79 65 6d 71 36 be ae b2 b6 3e ba 22 a2 a6 aa 2a 3a 26 2e 32 17 9f 8f 93 97 1f 9b 03 83 87 8b 0b 1b 07 0f 13 37 bf af b3 b7 3f bb 23 a3 a7 ab 2b 3b 27 2f 33 14 9c 8c 90 94 1c 98 00 80 84 88 08 18 04 0c 10 54 dc cc d0 d4 5c d8 40 c0 c4 c8 48 58 44 4c 50 74 fc ec f0 f4 7c f8 60 e0 e4 e8 68 78 64 6c 70 76 fe ee f2 f6 7e fa 62 e2 e6 ea 6a 7a 66 6e 72 16 9e 8e 92 96 1e 9a 02 82 86 8a 0a 1a 06 0e 12 35 bd ad b1 b5 3d b9 21 a1 a5 a9 29 39 25 2d 31 55 dd cd d1 d5 5d d9 41 c1 c5 c9 49 59 45 4d 51 77 ff ef f3 f7 7f fb 63 e3 e7 eb 6b 7b 67 6f 73 34 bc ac b0 b4 3c b8 20 a0 a4 a8 28 38 24 2c 30 56 de ce d2 d6 5e da 42 c2 c6 ca 4a 5a 46 4e 52 }

  condition:
    $a0
}