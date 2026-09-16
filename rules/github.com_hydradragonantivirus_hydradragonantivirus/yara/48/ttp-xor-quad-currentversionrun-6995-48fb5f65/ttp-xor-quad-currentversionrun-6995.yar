rule TTP_XOR_QUAD_CurrentVersionRun_6995 {
  strings:
    $key_6995 = { 3a fa [2] 1e f4 [2] 35 d8 [2] 1b fa [2] 0f e1 [2] 00 fb [2] 1e e6 [2] 1c e7 [2] 07 e1 [2] 1b e6 [2] 07 c9 }

  condition:
    any of them
}