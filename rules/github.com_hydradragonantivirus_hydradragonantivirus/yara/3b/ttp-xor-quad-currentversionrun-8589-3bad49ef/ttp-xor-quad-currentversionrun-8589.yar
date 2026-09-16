rule TTP_XOR_QUAD_CurrentVersionRun_8589 {
  strings:
    $key_8589 = { d6 e6 [2] f2 e8 [2] d9 c4 [2] f7 e6 [2] e3 fd [2] ec e7 [2] f2 fa [2] f0 fb [2] eb fd [2] f7 fa [2] eb d5 }

  condition:
    any of them
}