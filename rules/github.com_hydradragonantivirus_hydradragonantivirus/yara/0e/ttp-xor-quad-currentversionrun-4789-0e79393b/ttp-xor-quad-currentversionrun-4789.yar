rule TTP_XOR_QUAD_CurrentVersionRun_4789 {
  strings:
    $key_4789 = { 14 e6 [2] 30 e8 [2] 1b c4 [2] 35 e6 [2] 21 fd [2] 2e e7 [2] 30 fa [2] 32 fb [2] 29 fd [2] 35 fa [2] 29 d5 }

  condition:
    any of them
}