rule TTP_XOR_QUAD_CurrentVersionRun_42b4 {
  strings:
    $key_42b4 = { 11 db [2] 35 d5 [2] 1e f9 [2] 30 db [2] 24 c0 [2] 2b da [2] 35 c7 [2] 37 c6 [2] 2c c0 [2] 30 c7 [2] 2c e8 }

  condition:
    any of them
}