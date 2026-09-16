rule TTP_XOR_QUAD_CurrentVersionRun_7489 {
  strings:
    $key_7489 = { 27 e6 [2] 03 e8 [2] 28 c4 [2] 06 e6 [2] 12 fd [2] 1d e7 [2] 03 fa [2] 01 fb [2] 1a fd [2] 06 fa [2] 1a d5 }

  condition:
    any of them
}