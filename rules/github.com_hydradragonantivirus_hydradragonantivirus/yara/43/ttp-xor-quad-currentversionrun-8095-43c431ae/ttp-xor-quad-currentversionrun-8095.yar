rule TTP_XOR_QUAD_CurrentVersionRun_8095 {
  strings:
    $key_8095 = { d3 fa [2] f7 f4 [2] dc d8 [2] f2 fa [2] e6 e1 [2] e9 fb [2] f7 e6 [2] f5 e7 [2] ee e1 [2] f2 e6 [2] ee c9 }

  condition:
    any of them
}