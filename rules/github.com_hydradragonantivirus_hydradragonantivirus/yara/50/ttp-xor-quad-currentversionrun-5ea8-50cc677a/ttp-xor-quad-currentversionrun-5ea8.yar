rule TTP_XOR_QUAD_CurrentVersionRun_5ea8 {
  strings:
    $key_5ea8 = { 0d c7 [2] 29 c9 [2] 02 e5 [2] 2c c7 [2] 38 dc [2] 37 c6 [2] 29 db [2] 2b da [2] 30 dc [2] 2c db [2] 30 f4 }

  condition:
    any of them
}