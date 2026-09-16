rule TTP_XOR_QUAD_CurrentVersionRun_5b89 {
  strings:
    $key_5b89 = { 08 e6 [2] 2c e8 [2] 07 c4 [2] 29 e6 [2] 3d fd [2] 32 e7 [2] 2c fa [2] 2e fb [2] 35 fd [2] 29 fa [2] 35 d5 }

  condition:
    any of them
}