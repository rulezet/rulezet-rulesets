rule TTP_XOR_QUAD_CurrentVersionRun_5b85 {
  strings:
    $key_5b85 = { 08 ea [2] 2c e4 [2] 07 c8 [2] 29 ea [2] 3d f1 [2] 32 eb [2] 2c f6 [2] 2e f7 [2] 35 f1 [2] 29 f6 [2] 35 d9 }

  condition:
    any of them
}