rule CRC_8_CCITT_poly_0xe1__8_byt_refl_False_ {
  strings:
    $a0 = { 00 e1 23 c2 46 a7 65 84 8c 6d af 4e ca 2b e9 08 f9 18 da 3b bf 5e 9c 7d 75 94 56 b7 33 d2 10 f1 13 f2 30 d1 55 b4 76 97 9f 7e bc 5d d9 38 fa 1b ea 0b c9 28 ac 4d 8f 6e 66 87 45 a4 20 c1 03 e2 26 c7 05 e4 60 81 43 a2 aa 4b 89 68 ec 0d cf 2e df 3e fc 1d 99 78 ba 5b 53 b2 70 91 15 f4 36 d7 35 d4 16 f7 73 92 50 b1 b9 58 9a 7b ff 1e dc 3d cc 2d ef 0e 8a 6b a9 48 40 a1 63 82 06 e7 25 c4 4c ad 6f 8e 0a eb 29 c8 c0 21 e3 02 86 67 a5 44 b5 54 96 77 f3 12 d0 31 39 d8 1a fb 7f 9e 5c bd 5f be 7c 9d 19 f8 3a db d3 32 f0 11 95 74 b6 57 a6 47 85 64 e0 01 c3 22 2a cb 09 e8 6c 8d 4f ae 6a 8b 49 a8 2c cd 0f ee e6 07 c5 24 a0 41 83 62 93 72 b0 51 d5 34 f6 17 1f fe 3c dd 59 b8 7a 9b 79 98 5a bb 3f de 1c fd f5 14 d6 37 b3 52 90 71 80 61 a3 42 c6 27 e5 04 0c ed 2f ce 4a ab 69 88 }

  condition:
    $a0
}