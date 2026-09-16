rule TTP_XOR_QUAD_CurrentVersionRun_1e89 {
  strings:
    $key_1e89 = { 4d e6 [2] 69 e8 [2] 42 c4 [2] 6c e6 [2] 78 fd [2] 77 e7 [2] 69 fa [2] 6b fb [2] 70 fd [2] 6c fa [2] 70 d5 }

  condition:
    any of them
}