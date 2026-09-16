rule TTP_XOR_QUAD_CurrentVersionRun_5b8b {
  strings:
    $key_5b8b = { 08 e4 [2] 2c ea [2] 07 c6 [2] 29 e4 [2] 3d ff [2] 32 e5 [2] 2c f8 [2] 2e f9 [2] 35 ff [2] 29 f8 [2] 35 d7 }

  condition:
    any of them
}