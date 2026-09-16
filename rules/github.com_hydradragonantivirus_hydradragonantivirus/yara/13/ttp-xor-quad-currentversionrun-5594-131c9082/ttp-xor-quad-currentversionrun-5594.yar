rule TTP_XOR_QUAD_CurrentVersionRun_5594 {
  strings:
    $key_5594 = { 06 fb [2] 22 f5 [2] 09 d9 [2] 27 fb [2] 33 e0 [2] 3c fa [2] 22 e7 [2] 20 e6 [2] 3b e0 [2] 27 e7 [2] 3b c8 }

  condition:
    any of them
}