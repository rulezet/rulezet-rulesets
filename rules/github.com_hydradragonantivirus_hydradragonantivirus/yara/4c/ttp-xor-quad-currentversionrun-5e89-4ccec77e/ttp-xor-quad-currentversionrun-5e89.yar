rule TTP_XOR_QUAD_CurrentVersionRun_5e89 {
  strings:
    $key_5e89 = { 0d e6 [2] 29 e8 [2] 02 c4 [2] 2c e6 [2] 38 fd [2] 37 e7 [2] 29 fa [2] 2b fb [2] 30 fd [2] 2c fa [2] 30 d5 }

  condition:
    any of them
}