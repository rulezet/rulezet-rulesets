rule TTP_XOR_QUAD_CurrentVersionRun_8695 {
  strings:
    $key_8695 = { d5 fa [2] f1 f4 [2] da d8 [2] f4 fa [2] e0 e1 [2] ef fb [2] f1 e6 [2] f3 e7 [2] e8 e1 [2] f4 e6 [2] e8 c9 }

  condition:
    any of them
}