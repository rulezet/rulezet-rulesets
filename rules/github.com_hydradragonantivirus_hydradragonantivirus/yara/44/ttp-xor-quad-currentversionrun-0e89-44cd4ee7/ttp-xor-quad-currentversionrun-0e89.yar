rule TTP_XOR_QUAD_CurrentVersionRun_0e89 {
  strings:
    $key_0e89 = { 5d e6 [2] 79 e8 [2] 52 c4 [2] 7c e6 [2] 68 fd [2] 67 e7 [2] 79 fa [2] 7b fb [2] 60 fd [2] 7c fa [2] 60 d5 }

  condition:
    any of them
}