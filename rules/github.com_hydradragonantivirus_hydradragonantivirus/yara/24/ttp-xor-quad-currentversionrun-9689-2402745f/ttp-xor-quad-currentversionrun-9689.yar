rule TTP_XOR_QUAD_CurrentVersionRun_9689 {
  strings:
    $key_9689 = { c5 e6 [2] e1 e8 [2] ca c4 [2] e4 e6 [2] f0 fd [2] ff e7 [2] e1 fa [2] e3 fb [2] f8 fd [2] e4 fa [2] f8 d5 }

  condition:
    any of them
}