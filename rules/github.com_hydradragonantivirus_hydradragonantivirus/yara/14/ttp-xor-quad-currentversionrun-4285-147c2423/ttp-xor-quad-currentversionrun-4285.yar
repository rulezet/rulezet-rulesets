rule TTP_XOR_QUAD_CurrentVersionRun_4285 {
  strings:
    $key_4285 = { 11 ea [2] 35 e4 [2] 1e c8 [2] 30 ea [2] 24 f1 [2] 2b eb [2] 35 f6 [2] 37 f7 [2] 2c f1 [2] 30 f6 [2] 2c d9 }

  condition:
    any of them
}