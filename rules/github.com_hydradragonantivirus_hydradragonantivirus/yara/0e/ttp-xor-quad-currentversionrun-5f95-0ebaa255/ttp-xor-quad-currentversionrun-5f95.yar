rule TTP_XOR_QUAD_CurrentVersionRun_5f95 {
  strings:
    $key_5f95 = { 0c fa [2] 28 f4 [2] 03 d8 [2] 2d fa [2] 39 e1 [2] 36 fb [2] 28 e6 [2] 2a e7 [2] 31 e1 [2] 2d e6 [2] 31 c9 }

  condition:
    any of them
}