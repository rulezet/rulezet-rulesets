rule TTP_XOR_QUAD_CurrentVersionRun_9b94 {
  strings:
    $key_9b94 = { c8 fb [2] ec f5 [2] c7 d9 [2] e9 fb [2] fd e0 [2] f2 fa [2] ec e7 [2] ee e6 [2] f5 e0 [2] e9 e7 [2] f5 c8 }

  condition:
    any of them
}