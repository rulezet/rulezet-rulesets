rule TTP_XOR_QUAD_CurrentVersionRun_8389 {
  strings:
    $key_8389 = { d0 e6 [2] f4 e8 [2] df c4 [2] f1 e6 [2] e5 fd [2] ea e7 [2] f4 fa [2] f6 fb [2] ed fd [2] f1 fa [2] ed d5 }

  condition:
    any of them
}