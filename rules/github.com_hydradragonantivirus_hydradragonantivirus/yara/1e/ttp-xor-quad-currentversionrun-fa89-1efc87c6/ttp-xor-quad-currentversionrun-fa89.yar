rule TTP_XOR_QUAD_CurrentVersionRun_fa89 {
  strings:
    $key_fa89 = { a9 e6 [2] 8d e8 [2] a6 c4 [2] 88 e6 [2] 9c fd [2] 93 e7 [2] 8d fa [2] 8f fb [2] 94 fd [2] 88 fa [2] 94 d5 }

  condition:
    any of them
}