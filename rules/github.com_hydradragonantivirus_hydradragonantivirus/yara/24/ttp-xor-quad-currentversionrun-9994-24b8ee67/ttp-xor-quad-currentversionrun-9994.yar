rule TTP_XOR_QUAD_CurrentVersionRun_9994 {
  strings:
    $key_9994 = { ca fb [2] ee f5 [2] c5 d9 [2] eb fb [2] ff e0 [2] f0 fa [2] ee e7 [2] ec e6 [2] f7 e0 [2] eb e7 [2] f7 c8 }

  condition:
    any of them
}