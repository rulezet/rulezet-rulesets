rule ascii_to_ebcdic_table__8_byt_256_ {
  strings:
    $a0 = { 00 01 02 03 37 2d 2e 2f 16 05 15 0b 0c 0d 0e 0f 10 11 12 13 3c 3d 32 26 18 19 3f 27 1c 1d 1e 1f 40 5a 7f 7b 5b 6c 50 7d 4d 5d 5c 4e 6b 60 4b 61 f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 7a 5e 4c 7e 6e 6f 7c c1 c2 c3 c4 c5 c6 c7 c8 c9 d1 d2 d3 d4 d5 d6 d7 d8 d9 e2 e3 e4 e5 e6 e7 e8 e9 bb bc bd 6a 6d 4a 81 82 83 84 85 86 87 88 89 91 92 93 94 95 96 97 98 99 a2 a3 a4 a5 a6 a7 a8 a9 fb 4f fd ff 07 20 21 22 23 24 04 06 08 28 29 2a 2b 2c 09 0a 14 30 31 25 33 34 35 36 17 38 39 3a 3b 1a 1b 3e 5f 41 aa b0 b1 9f b2 d0 b5 79 b4 9a 8a ba ca af a1 90 8f ea fa be a0 b6 b3 9d da 9b 8b b7 b8 b9 ab 64 65 62 66 63 67 9e 68 74 71 72 73 78 75 76 77 ac 69 ed ee eb ef ec bf 80 e0 fe dd fc ad ae 59 44 45 42 46 43 47 9c 48 54 51 52 53 58 55 56 57 8c 49 cd ce cb cf cc e1 70 c0 de db dc 8d 8e df }

  condition:
    $a0
}