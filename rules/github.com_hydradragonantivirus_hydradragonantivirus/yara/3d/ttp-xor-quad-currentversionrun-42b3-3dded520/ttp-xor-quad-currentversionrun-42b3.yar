rule TTP_XOR_QUAD_CurrentVersionRun_42b3 {
  strings:
    $key_42b3 = { 11 dc [2] 35 d2 [2] 1e fe [2] 30 dc [2] 24 c7 [2] 2b dd [2] 35 c0 [2] 37 c1 [2] 2c c7 [2] 30 c0 [2] 2c ef }

  condition:
    any of them
}