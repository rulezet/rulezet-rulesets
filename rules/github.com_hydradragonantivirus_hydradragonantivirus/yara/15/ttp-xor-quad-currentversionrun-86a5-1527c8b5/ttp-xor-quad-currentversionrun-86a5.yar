rule TTP_XOR_QUAD_CurrentVersionRun_86a5 {
  strings:
    $key_86a5 = { d5 ca [2] f1 c4 [2] da e8 [2] f4 ca [2] e0 d1 [2] ef cb [2] f1 d6 [2] f3 d7 [2] e8 d1 [2] f4 d6 [2] e8 f9 }

  condition:
    any of them
}