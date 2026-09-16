rule Haval_mc3__32_big_128_ {
  strings:
    $a0 = { 9c 30 d5 39 2a f2 60 13 c5 d1 b0 23 28 60 85 f0 ca 41 79 18 b8 db 38 ef 8e 79 dc b0 60 3a 18 0e 6c 9e 0e 8b b0 1e 8a 3e d7 15 77 c1 bd 31 4b 27 78 af 2f da 55 60 5c 60 e6 55 25 f3 aa 55 ab 94 57 48 98 62 63 e8 14 40 55 ca 39 6a 2a ab 10 b6 b4 cc 5c 34 11 41 e8 ce a1 54 86 af 7c 72 e9 93 b3 ee 14 11 63 6f bc 2a 2b a9 c5 5d 74 18 31 f6 ce 5c 3e 16 9b 87 93 1e af d6 ba 33 6c 24 cf 5c }

  condition:
    $a0
}