rule TTP_XOR_QUAD_CurrentVersionRun_8189 {
  strings:
    $key_8189 = { d2 e6 [2] f6 e8 [2] dd c4 [2] f3 e6 [2] e7 fd [2] e8 e7 [2] f6 fa [2] f4 fb [2] ef fd [2] f3 fa [2] ef d5 }

  condition:
    any of them
}