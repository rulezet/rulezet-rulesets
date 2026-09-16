rule TTP_XOR_QUAD_CurrentVersionRun_2e89 {
  strings:
    $key_2e89 = { 7d e6 [2] 59 e8 [2] 72 c4 [2] 5c e6 [2] 48 fd [2] 47 e7 [2] 59 fa [2] 5b fb [2] 40 fd [2] 5c fa [2] 40 d5 }

  condition:
    any of them
}