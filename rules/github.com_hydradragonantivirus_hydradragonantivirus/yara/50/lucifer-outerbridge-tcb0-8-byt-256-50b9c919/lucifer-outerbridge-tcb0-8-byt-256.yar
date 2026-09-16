rule Lucifer__outerbridge__TCB0__8_byt_256_ {
  strings:
    $a0 = { 57 15 75 36 17 37 14 54 74 76 16 35 55 77 34 56 df 9d fd be 9f bf 9c dc fc fe 9e bd dd ff bc de cf 8d ed ae 8f af 8c cc ec ee 8e ad cd ef ac ce d3 91 f1 b2 93 b3 90 d0 f0 f2 92 b1 d1 f3 b0 d2 d7 95 f5 b6 97 b7 94 d4 f4 f6 96 b5 d5 f7 b4 d6 5f 1d 7d 3e 1f 3f 1c 5c 7c 7e 1e 3d 5d 7f 3c 5e db 99 f9 ba 9b bb 98 d8 f8 fa 9a b9 d9 fb b8 da 43 01 61 22 03 23 00 40 60 62 02 21 41 63 20 42 c3 81 e1 a2 83 a3 80 c0 e0 e2 82 a1 c1 e3 a0 c2 c7 85 e5 a6 87 a7 84 c4 e4 e6 86 a5 c5 e7 a4 c6 cb 89 e9 aa 8b ab 88 c8 e8 ea 8a a9 c9 eb a8 ca 4b 09 69 2a 0b 2b 08 48 68 6a 0a 29 49 6b 28 4a 5b 19 79 3a 1b 3b 18 58 78 7a 1a 39 59 7b 38 5a 47 05 65 26 07 27 04 44 64 66 06 25 45 67 24 46 4f 0d 6d 2e 0f 2f 0c 4c 6c 6e 0e 2d 4d 6f 2c 4e 53 11 71 32 13 33 10 50 70 72 12 31 51 73 30 52 }

  condition:
    $a0
}