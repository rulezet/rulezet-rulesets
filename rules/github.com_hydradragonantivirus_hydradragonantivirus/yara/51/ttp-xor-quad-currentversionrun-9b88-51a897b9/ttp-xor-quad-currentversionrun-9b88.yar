rule TTP_XOR_QUAD_CurrentVersionRun_9b88 {
  strings:
    $key_9b88 = { c8 e7 [2] ec e9 [2] c7 c5 [2] e9 e7 [2] fd fc [2] f2 e6 [2] ec fb [2] ee fa [2] f5 fc [2] e9 fb [2] f5 d4 }

  condition:
    any of them
}