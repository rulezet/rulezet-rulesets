rule Camellia_s3__8_byt_256_ {
  strings:
    $a0 = { 38 41 16 76 d9 93 60 f2 72 c2 ab 9a 75 06 57 a0 91 f7 b5 c9 a2 8c d2 90 f6 07 a7 27 8e b2 49 de 43 5c d7 c7 3e f5 8f 67 1f 18 6e af 2f e2 85 0d 53 f0 9c 65 ea a3 ae 9e ec 80 2d 6b a8 2b 36 a6 c5 86 4d 33 fd 66 58 96 3a 09 95 10 78 d8 42 cc ef 26 e5 61 1a 3f 3b 82 b6 db d4 98 e8 8b 02 eb 0a 2c 1d b0 6f 8d 88 0e 19 87 4e 0b a9 0c 79 11 7f 22 e7 59 e1 da 3d c8 12 04 74 54 30 7e b4 28 55 68 50 be d0 c4 31 cb 2a ad 0f ca 70 ff 32 69 08 62 00 24 d1 fb ba ed 45 81 73 6d 84 9f ee 4a c3 2e c1 01 e6 25 48 99 b9 b3 7b f9 ce bf df 71 29 cd 6c 13 64 9b 63 9d c0 4b b7 a5 89 5f b1 17 f4 bc d3 46 cf 37 5e 47 94 fa fc 5b 97 fe 5a ac 3c 4c 03 35 f3 23 b8 5d 6a 92 d5 21 44 51 c6 7d 39 83 dc aa 7c 77 56 05 1b a4 15 34 1e 1c f8 52 20 14 e9 bd dd e4 a1 e0 8a f1 d6 7a bb e3 40 4f }

  condition:
    $a0
}