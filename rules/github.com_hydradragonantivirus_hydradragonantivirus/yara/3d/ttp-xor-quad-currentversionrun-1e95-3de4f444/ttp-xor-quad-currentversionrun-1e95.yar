rule TTP_XOR_QUAD_CurrentVersionRun_1e95 {
  strings:
    $key_1e95 = { 4d fa [2] 69 f4 [2] 42 d8 [2] 6c fa [2] 78 e1 [2] 77 fb [2] 69 e6 [2] 6b e7 [2] 70 e1 [2] 6c e6 [2] 70 c9 }

  condition:
    any of them
}