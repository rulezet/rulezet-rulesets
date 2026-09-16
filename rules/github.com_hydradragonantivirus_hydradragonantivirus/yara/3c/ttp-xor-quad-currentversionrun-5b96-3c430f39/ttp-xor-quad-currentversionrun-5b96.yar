rule TTP_XOR_QUAD_CurrentVersionRun_5b96 {
  strings:
    $key_5b96 = { 08 f9 [2] 2c f7 [2] 07 db [2] 29 f9 [2] 3d e2 [2] 32 f8 [2] 2c e5 [2] 2e e4 [2] 35 e2 [2] 29 e5 [2] 35 ca }

  condition:
    any of them
}