rule libfaad2_sa_quant__flt64___64_lil_128_ {
  strings:
    $a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 bb 27 0f 0b b5 a6 a9 3f 52 49 9d 80 26 c2 c6 3f 50 fc 18 73 d7 12 b2 3f b7 d1 00 de 02 09 d2 3f 46 b6 f3 fd d4 78 b9 3f 82 e2 c7 98 bb 96 dc 3f 63 ee 5a 42 3e e8 c1 3f 3c 4e d1 91 5c fe e1 3f b1 e1 e9 95 b2 0c c9 3f 2c d4 9a e6 1d a7 e6 3f 3e e8 d9 ac fa 5c d1 3f f6 97 dd 93 87 85 ec 3f ea 95 b2 0c 71 ac d7 3f 00 00 00 00 00 00 f0 3f }

  condition:
    $a0
}