rule TTP_XOR_QUAD_CurrentVersionRun_4895 {
  strings:
    $key_4895 = { 1b fa [2] 3f f4 [2] 14 d8 [2] 3a fa [2] 2e e1 [2] 21 fb [2] 3f e6 [2] 3d e7 [2] 26 e1 [2] 3a e6 [2] 26 c9 }

  condition:
    any of them
}