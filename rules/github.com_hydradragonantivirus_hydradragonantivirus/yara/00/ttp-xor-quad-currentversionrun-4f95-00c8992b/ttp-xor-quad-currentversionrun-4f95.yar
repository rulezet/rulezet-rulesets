rule TTP_XOR_QUAD_CurrentVersionRun_4f95 {
  strings:
    $key_4f95 = { 1c fa [2] 38 f4 [2] 13 d8 [2] 3d fa [2] 29 e1 [2] 26 fb [2] 38 e6 [2] 3a e7 [2] 21 e1 [2] 3d e6 [2] 21 c9 }

  condition:
    any of them
}