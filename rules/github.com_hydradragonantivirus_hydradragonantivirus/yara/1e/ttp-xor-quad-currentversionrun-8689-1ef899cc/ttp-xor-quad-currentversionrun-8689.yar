rule TTP_XOR_QUAD_CurrentVersionRun_8689 {
  strings:
    $key_8689 = { d5 e6 [2] f1 e8 [2] da c4 [2] f4 e6 [2] e0 fd [2] ef e7 [2] f1 fa [2] f3 fb [2] e8 fd [2] f4 fa [2] e8 d5 }

  condition:
    any of them
}