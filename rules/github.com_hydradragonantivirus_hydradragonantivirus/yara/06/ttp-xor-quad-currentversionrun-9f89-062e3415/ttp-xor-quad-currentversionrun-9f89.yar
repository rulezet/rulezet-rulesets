rule TTP_XOR_QUAD_CurrentVersionRun_9f89 {
  strings:
    $key_9f89 = { cc e6 [2] e8 e8 [2] c3 c4 [2] ed e6 [2] f9 fd [2] f6 e7 [2] e8 fa [2] ea fb [2] f1 fd [2] ed fa [2] f1 d5 }

  condition:
    any of them
}