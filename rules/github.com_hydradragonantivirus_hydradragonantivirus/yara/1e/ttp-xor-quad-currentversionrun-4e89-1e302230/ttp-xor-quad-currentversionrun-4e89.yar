rule TTP_XOR_QUAD_CurrentVersionRun_4e89 {
  strings:
    $key_4e89 = { 1d e6 [2] 39 e8 [2] 12 c4 [2] 3c e6 [2] 28 fd [2] 27 e7 [2] 39 fa [2] 3b fb [2] 20 fd [2] 3c fa [2] 20 d5 }

  condition:
    any of them
}