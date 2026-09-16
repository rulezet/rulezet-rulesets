rule TTP_XOR_QUAD_CurrentVersionRun_3e95 {
  strings:
    $key_3e95 = { 6d fa [2] 49 f4 [2] 62 d8 [2] 4c fa [2] 58 e1 [2] 57 fb [2] 49 e6 [2] 4b e7 [2] 50 e1 [2] 4c e6 [2] 50 c9 }

  condition:
    any of them
}