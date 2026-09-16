rule Dolby_window_dolby_win_32__flt32___32_big_128_ {
  strings:
    $a0 = { 38 b7 b1 47 3a 74 5d 46 3b 52 77 61 3c 04 ba 03 3c 8c 47 b1 3d 03 5e 02 3d 60 96 3f 3d b2 74 74 3e 05 6b 5b 3e 3d 55 42 3e 80 50 c8 3e a6 f4 ee 3e d1 5f 7e 3e fd ec 0b 3f 15 59 4f 3f 2a de ac 3f 3e a1 16 3f 4f eb a3 3f 5e 4c 93 3f 69 9d dc 3f 72 01 c7 3f 77 d4 84 3f 7b 96 0a 3f 7d d1 59 3f 7f 06 ba 3f 7f 9d 69 3f 7f de 49 3f 7f f6 64 3f 7f fd d9 3f 7f ff a9 3f 7f ff f9 3f 80 00 00 }

  condition:
    $a0
}