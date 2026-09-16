rule TTP_XOR_QUAD_CurrentVersionRun_9389 {
  strings:
    $key_9389 = { c0 e6 [2] e4 e8 [2] cf c4 [2] e1 e6 [2] f5 fd [2] fa e7 [2] e4 fa [2] e6 fb [2] fd fd [2] e1 fa [2] fd d5 }

  condition:
    any of them
}