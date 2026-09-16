rule Playgate_decoding_encoding_algorithm__8_byt_256_ {
  strings:
    $a0 = { 28 e5 ba 0a 99 20 6f 0f 38 90 d8 34 c0 54 96 d9 aa 5d a4 45 fb b4 ac 27 42 e9 8b 30 29 a1 5b 97 73 cc 7a 8d ce 92 95 e7 98 e8 de 5f 9a 6e 6d 8e 62 b0 fa d5 d2 74 40 2d 64 02 be 88 71 4f 61 4d fc 91 81 a6 4a ea 50 e3 a3 66 67 f2 da f5 4c dc 23 fe 36 86 04 3e c2 60 ef f0 ee e1 06 ae 8a 63 8c a7 72 bc 82 69 46 af e6 eb 09 1f db 0b b8 5c 11 b6 07 6b 18 4b 89 48 13 9c 3f 55 17 35 ed dd 79 5e 2e 3a ad 3b b1 15 b3 6c e0 f8 f7 9f 03 2c 56 7f 1a 87 0d e2 78 4e 2f 1b d6 51 cf 1d d7 ff d4 ab 00 08 33 f3 a8 c5 c1 ec 52 f4 68 7c 84 d3 80 57 01 a2 b7 d0 70 cb fd 3c 9b 14 65 58 12 26 bb a5 05 bd ca b2 b5 76 37 2a cd 39 1e 47 5a 85 8f 22 b9 53 6a 59 10 c7 7e 1c 44 f1 25 c8 83 9e c3 7d bf 49 32 19 c4 d1 77 f6 c6 9d a9 7b a0 e4 41 0c 93 c9 0e df 2b 24 f9 75 3d 94 21 43 16 31 }

  condition:
    $a0
}