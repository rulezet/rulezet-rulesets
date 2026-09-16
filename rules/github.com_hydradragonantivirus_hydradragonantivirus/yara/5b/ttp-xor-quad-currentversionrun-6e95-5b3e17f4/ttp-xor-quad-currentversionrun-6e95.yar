rule TTP_XOR_QUAD_CurrentVersionRun_6e95 {
  strings:
    $key_6e95 = { 3d fa [2] 19 f4 [2] 32 d8 [2] 1c fa [2] 08 e1 [2] 07 fb [2] 19 e6 [2] 1b e7 [2] 00 e1 [2] 1c e6 [2] 00 c9 }

  condition:
    any of them
}