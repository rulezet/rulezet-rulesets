rule TTP_XOR_QUAD_CurrentVersionRun_8795 {
  strings:
    $key_8795 = { d4 fa [2] f0 f4 [2] db d8 [2] f5 fa [2] e1 e1 [2] ee fb [2] f0 e6 [2] f2 e7 [2] e9 e1 [2] f5 e6 [2] e9 c9 }

  condition:
    any of them
}