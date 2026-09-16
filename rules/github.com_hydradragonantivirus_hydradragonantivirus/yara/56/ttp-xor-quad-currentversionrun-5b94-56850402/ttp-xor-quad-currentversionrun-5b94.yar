rule TTP_XOR_QUAD_CurrentVersionRun_5b94 {
  strings:
    $key_5b94 = { 08 fb [2] 2c f5 [2] 07 d9 [2] 29 fb [2] 3d e0 [2] 32 fa [2] 2c e7 [2] 2e e6 [2] 35 e0 [2] 29 e7 [2] 35 c8 }

  condition:
    any of them
}