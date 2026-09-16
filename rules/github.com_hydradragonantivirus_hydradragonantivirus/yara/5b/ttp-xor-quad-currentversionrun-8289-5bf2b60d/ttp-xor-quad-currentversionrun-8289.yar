rule TTP_XOR_QUAD_CurrentVersionRun_8289 {
  strings:
    $key_8289 = { d1 e6 [2] f5 e8 [2] de c4 [2] f0 e6 [2] e4 fd [2] eb e7 [2] f5 fa [2] f7 fb [2] ec fd [2] f0 fa [2] ec d5 }

  condition:
    any of them
}