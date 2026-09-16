rule Teamsound_join_password_algorithm__8_byt_256_ {
  strings:
    $a0 = { d4 70 5f 69 c3 10 ec f5 62 1c f3 39 c9 f9 bc 7c d6 7d 2e e4 57 d2 4b 6b ce 0e eb 77 84 e9 cc 25 bb a8 40 3d 67 ad af 1f 1d 41 83 28 8c 6e 2d 06 9a dc a6 03 66 7e 29 8f dd 6f fe 3a 01 16 43 7b cf 64 9e 9b 23 c0 81 0f 18 3f 56 1b ea d0 8d 07 5d 0c 31 47 50 11 24 a3 ac d1 e2 ff c5 e6 5a fc 87 60 02 7a ae b0 3c 71 b7 fd 33 44 92 54 d7 65 e1 c4 b9 d9 21 4e 26 93 38 76 3b 9f f7 78 5e 3e fb 17 da 22 e3 48 4c 53 12 f2 0b 61 72 cd bd b8 ef a0 e5 7f 68 f6 51 73 1a b2 df 27 2b 0a 19 5b c7 90 8e aa 36 8a 6d 2f 00 e0 1e 85 c2 c8 91 ca d5 9d 04 0d 20 95 98 35 de a1 75 ba 9c 89 58 86 b4 49 d8 a7 a2 c1 b3 c6 4f f4 82 55 32 46 15 d3 52 fa ab be a5 6c 59 f8 bf 2a a4 14 e7 5c 2c 88 b1 6a 97 30 37 13 94 99 db 42 4d a9 f0 74 f1 05 b5 8b 45 09 ed 96 79 63 08 4a 34 cb 80 e8 b6 ee }

  condition:
    $a0
}