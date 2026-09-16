rule TTP_XOR_QUAD_CurrentVersionRun_7289 {
  strings:
    $key_7289 = { 21 e6 [2] 05 e8 [2] 2e c4 [2] 00 e6 [2] 14 fd [2] 1b e7 [2] 05 fa [2] 07 fb [2] 1c fd [2] 00 fa [2] 1c d5 }

  condition:
    any of them
}