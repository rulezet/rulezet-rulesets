rule TTP_XOR_QUAD_CurrentVersionRun_9995 {
  strings:
    $key_9995 = { ca fa [2] ee f4 [2] c5 d8 [2] eb fa [2] ff e1 [2] f0 fb [2] ee e6 [2] ec e7 [2] f7 e1 [2] eb e6 [2] f7 c9 }

  condition:
    any of them
}