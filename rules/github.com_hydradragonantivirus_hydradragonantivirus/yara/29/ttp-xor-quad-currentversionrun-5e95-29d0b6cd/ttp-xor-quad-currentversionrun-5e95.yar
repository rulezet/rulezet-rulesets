rule TTP_XOR_QUAD_CurrentVersionRun_5e95 {
  strings:
    $key_5e95 = { 0d fa [2] 29 f4 [2] 02 d8 [2] 2c fa [2] 38 e1 [2] 37 fb [2] 29 e6 [2] 2b e7 [2] 30 e1 [2] 2c e6 [2] 30 c9 }

  condition:
    any of them
}