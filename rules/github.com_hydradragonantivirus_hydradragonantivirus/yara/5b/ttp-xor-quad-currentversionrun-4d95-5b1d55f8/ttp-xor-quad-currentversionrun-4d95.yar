rule TTP_XOR_QUAD_CurrentVersionRun_4d95 {
  strings:
    $key_4d95 = { 1e fa [2] 3a f4 [2] 11 d8 [2] 3f fa [2] 2b e1 [2] 24 fb [2] 3a e6 [2] 38 e7 [2] 23 e1 [2] 3f e6 [2] 23 c9 }

  condition:
    any of them
}