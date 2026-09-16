rule RC2_tab_num_to_ebits__8_byt_256_ {
  strings:
    $a0 = { 5d be 9b 8b 11 99 6e 4d 59 f3 85 a6 3f b7 83 c5 e4 73 6b 3a 68 5a c0 47 a0 64 34 0c f1 d0 52 a5 b9 1e 96 43 41 d8 d4 2c db f8 07 77 2a ca eb ef 10 1c 16 0d 38 72 2f 89 c1 f9 80 c4 6d ae 30 3d ce 20 63 fe e6 1a c7 b8 50 e8 24 17 fc 25 6f bb 6a a3 44 53 d9 a2 01 ab bc b6 1f 98 ee 9a a7 2d 4f 9e 8e ac e0 c6 49 46 29 f4 94 8a af e1 5b c3 b3 7b 57 d1 7c 9c ed 87 40 8c e2 cb 93 14 c9 61 2e e5 cc f6 5e a8 5c d6 75 8d 62 95 58 69 76 a1 4a b5 55 09 78 33 82 d7 dd 79 f5 1b 0b de 26 21 28 74 04 97 56 df 3c f0 37 39 dc ff 06 a4 ea 42 08 da b4 71 b0 cf 12 7a 4e fa 6c 1d 84 00 c8 7f 91 45 aa 2b c2 b1 8f d5 ba f2 ad 19 b2 67 36 f7 0f 0a 92 7d e3 9d e9 90 3e 23 27 66 13 ec 81 15 bd 22 bf 9f 7e a9 51 4b 4c fb 02 d3 70 86 31 e7 3b 05 03 54 60 48 65 18 d2 cd 5f 32 88 0e 35 fd }

  condition:
    $a0
}