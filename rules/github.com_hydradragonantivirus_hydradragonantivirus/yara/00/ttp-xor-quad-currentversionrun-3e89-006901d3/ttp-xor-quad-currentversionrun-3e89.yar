rule TTP_XOR_QUAD_CurrentVersionRun_3e89 {
  strings:
    $key_3e89 = { 6d e6 [2] 49 e8 [2] 62 c4 [2] 4c e6 [2] 58 fd [2] 57 e7 [2] 49 fa [2] 4b fb [2] 50 fd [2] 4c fa [2] 50 d5 }

  condition:
    any of them
}