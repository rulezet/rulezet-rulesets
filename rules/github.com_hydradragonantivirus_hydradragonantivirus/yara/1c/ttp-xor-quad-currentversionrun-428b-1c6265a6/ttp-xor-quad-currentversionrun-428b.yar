rule TTP_XOR_QUAD_CurrentVersionRun_428b {
  strings:
    $key_428b = { 11 e4 [2] 35 ea [2] 1e c6 [2] 30 e4 [2] 24 ff [2] 2b e5 [2] 35 f8 [2] 37 f9 [2] 2c ff [2] 30 f8 [2] 2c d7 }

  condition:
    any of them
}