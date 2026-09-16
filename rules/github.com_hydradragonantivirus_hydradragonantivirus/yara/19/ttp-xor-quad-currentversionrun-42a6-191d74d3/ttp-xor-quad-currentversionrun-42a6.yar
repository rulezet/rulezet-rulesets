rule TTP_XOR_QUAD_CurrentVersionRun_42a6 {
  strings:
    $key_42a6 = { 11 c9 [2] 35 c7 [2] 1e eb [2] 30 c9 [2] 24 d2 [2] 2b c8 [2] 35 d5 [2] 37 d4 [2] 2c d2 [2] 30 d5 [2] 2c fa }

  condition:
    any of them
}