rule TTP_XOR_QUAD_CurrentVersionRun_0e95 {
  strings:
    $key_0e95 = { 5d fa [2] 79 f4 [2] 52 d8 [2] 7c fa [2] 68 e1 [2] 67 fb [2] 79 e6 [2] 7b e7 [2] 60 e1 [2] 7c e6 [2] 60 c9 }

  condition:
    any of them
}