rule TTP_XOR_QUAD_CurrentVersionRun_6e89 {
  strings:
    $key_6e89 = { 3d e6 [2] 19 e8 [2] 32 c4 [2] 1c e6 [2] 08 fd [2] 07 e7 [2] 19 fa [2] 1b fb [2] 00 fd [2] 1c fa [2] 00 d5 }

  condition:
    any of them
}