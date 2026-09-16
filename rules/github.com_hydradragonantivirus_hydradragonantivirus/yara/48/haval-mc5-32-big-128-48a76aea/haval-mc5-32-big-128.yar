rule Haval_mc5__32_big_128_ {
  strings:
    $a0 = { ba 3b f0 50 7e fb 2a 98 a1 f1 65 1d 39 af 01 76 66 ca 59 3e 82 43 0e 88 8c ee 86 19 45 6f 9f b4 7d 84 a5 c3 3b 8b 5e be e0 6f 75 d8 85 c1 20 73 40 1a 44 9f 56 c1 6a a6 4e d3 aa 62 36 3f 77 06 1b fe df 72 42 9b 02 3d 37 d0 d7 24 d0 0a 12 48 db 0f ea d3 49 f1 c0 9b 07 53 72 c9 80 99 1b 7b 25 d4 79 d8 f6 e8 de f7 e3 fe 50 1a b6 79 4c 3b 97 6c e0 bd 04 c0 06 ba c1 a9 4f b6 40 9f 60 c4 }

  condition:
    $a0
}