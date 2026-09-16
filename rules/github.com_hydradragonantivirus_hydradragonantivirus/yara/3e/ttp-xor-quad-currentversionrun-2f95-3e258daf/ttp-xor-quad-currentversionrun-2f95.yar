rule TTP_XOR_QUAD_CurrentVersionRun_2f95 {
  strings:
    $key_2f95 = { 7c fa [2] 58 f4 [2] 73 d8 [2] 5d fa [2] 49 e1 [2] 46 fb [2] 58 e6 [2] 5a e7 [2] 41 e1 [2] 5d e6 [2] 41 c9 }

  condition:
    any of them
}