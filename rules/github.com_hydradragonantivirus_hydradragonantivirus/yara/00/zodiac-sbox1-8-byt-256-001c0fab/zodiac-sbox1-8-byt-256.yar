rule Zodiac_sbox1__8_byt_256_ {
  strings:
    $a0 = { 2d f3 7c 6d 9d b5 26 74 f2 93 53 b0 f0 11 ed 83 78 b6 03 16 73 3b 1e 8e 70 bd 86 1b 47 7e 24 56 f1 77 88 46 97 b1 ba a3 b7 10 0a c5 37 b3 c9 5a 28 ac 64 a5 ec ab aa c6 67 95 58 0d f8 9a f6 6e 66 dc 05 3d d3 8a c3 d8 89 6a e9 36 49 43 bf eb d4 96 9b 68 a0 65 5d 57 92 1f d5 71 5c bb 22 c1 be 7b bc 99 63 94 5f 2a 61 b8 34 32 19 fd fb 17 40 e6 51 1d 41 44 8f 29 dd 04 80 de e7 31 d6 7f 01 a2 f7 39 da 6f 23 ca fe 3a d0 1c d1 30 3e 12 a1 cd 0f e0 a8 af 82 59 2c f5 7d ad b2 ef c2 87 ce 75 06 13 02 90 4f 2e 72 33 85 c0 8d cf a9 81 e2 c4 27 2f 6c 7a 9f 52 e1 15 38 2b fc 20 42 c7 08 e4 09 55 5e 8c 14 76 60 ff df d7 98 fa 0b 21 00 1a f9 a6 b9 e8 9e 62 4c d9 91 50 d2 ee 18 b4 07 84 ea 5b a4 c8 0e cb 48 69 4b 4e 9c 35 79 45 4d 54 e5 25 3c 0c 4a 8b 3f cc a7 db 6b ae f4 e3 }

  condition:
    $a0
}