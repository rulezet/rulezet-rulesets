rule TTP_XOR_QUAD_CurrentVersionRun_8495 {
  strings:
    $key_8495 = { d7 fa [2] f3 f4 [2] d8 d8 [2] f6 fa [2] e2 e1 [2] ed fb [2] f3 e6 [2] f1 e7 [2] ea e1 [2] f6 e6 [2] ea c9 }

  condition:
    any of them
}