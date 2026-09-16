rule libavcodec_imc_exp_tab__flt64___64_lil_256_ {
  strings:
    $a0 = { 4c 01 7d e3 ea 4e 27 3f 11 43 20 0f 6c b9 34 3f 53 78 10 bf 42 6d 42 3f fc a9 f1 d2 4d 62 50 3f 9f 41 5c 9c a5 22 5d 3f d6 53 e8 12 c7 e7 69 3f 67 96 d4 6e 93 08 77 3f 7b 14 ae 47 e1 7a 84 3f 04 a9 b9 81 a7 35 92 3f 66 34 d1 6b dc 30 a0 3f 01 bc 89 4a b8 ca ac 3f 9a 99 99 99 99 99 b9 3f 45 13 28 62 11 c3 c6 3f 7f 81 c5 86 13 3d d4 3f 81 15 96 2e b3 fe e1 3f 00 00 00 00 00 00 f0 3f 16 18 b2 ba d5 73 fc 3f df e1 76 68 58 4c 09 40 e1 9a 3b fa 5f 7e 16 40 00 00 00 00 00 00 24 40 0e 4f af 94 65 c8 31 40 56 9a 94 82 6e 9f 3f 40 99 81 ca f8 f7 1d 4c 40 00 00 00 00 00 00 59 40 d1 22 db f9 7e 3a 66 40 76 e0 9c 11 a5 c3 73 40 00 91 7e fb ba 92 81 40 00 00 00 00 00 40 8f 40 85 eb 51 b8 1e c9 9b 40 93 18 04 56 8e b4 a8 40 3f 35 5e ba 69 f7 b5 40 00 00 00 00 00 88 c3 40 }

  condition:
    $a0
}