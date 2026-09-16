rule TTP_XOR_QUAD_CurrentVersionRun_9b89 {
  strings:
    $key_9b89 = { c8 e6 [2] ec e8 [2] c7 c4 [2] e9 e6 [2] fd fd [2] f2 e7 [2] ec fa [2] ee fb [2] f5 fd [2] e9 fa [2] f5 d5 }

  condition:
    any of them
}