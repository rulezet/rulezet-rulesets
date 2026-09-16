rule TTP_XOR_QUAD_CurrentVersionRun_4297 {
  strings:
    $key_4297 = { 11 f8 [2] 35 f6 [2] 1e da [2] 30 f8 [2] 24 e3 [2] 2b f9 [2] 35 e4 [2] 37 e5 [2] 2c e3 [2] 30 e4 [2] 2c cb }

  condition:
    any of them
}