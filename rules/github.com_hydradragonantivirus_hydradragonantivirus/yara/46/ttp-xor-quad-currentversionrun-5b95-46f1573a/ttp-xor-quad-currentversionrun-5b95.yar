rule TTP_XOR_QUAD_CurrentVersionRun_5b95 {
  strings:
    $key_5b95 = { 08 fa [2] 2c f4 [2] 07 d8 [2] 29 fa [2] 3d e1 [2] 32 fb [2] 2c e6 [2] 2e e7 [2] 35 e1 [2] 29 e6 [2] 35 c9 }

  condition:
    any of them
}