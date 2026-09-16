rule TTP_XOR_QUAD_CurrentVersionRun_86b7 {
  strings:
    $key_86b7 = { d5 d8 [2] f1 d6 [2] da fa [2] f4 d8 [2] e0 c3 [2] ef d9 [2] f1 c4 [2] f3 c5 [2] e8 c3 [2] f4 c4 [2] e8 eb }

  condition:
    any of them
}