rule TTP_XOR_QUAD_CurrentVersionRun_9989 {
  strings:
    $key_9989 = { ca e6 [2] ee e8 [2] c5 c4 [2] eb e6 [2] ff fd [2] f0 e7 [2] ee fa [2] ec fb [2] f7 fd [2] eb fa [2] f7 d5 }

  condition:
    any of them
}