rule TTP_XOR_QUAD_CurrentVersionRun_8595 {
  strings:
    $key_8595 = { d6 fa [2] f2 f4 [2] d9 d8 [2] f7 fa [2] e3 e1 [2] ec fb [2] f2 e6 [2] f0 e7 [2] eb e1 [2] f7 e6 [2] eb c9 }

  condition:
    any of them
}