rule TTP_XOR_QUAD_CurrentVersionRun_0895 {
  strings:
    $key_0895 = { 5b fa [2] 7f f4 [2] 54 d8 [2] 7a fa [2] 6e e1 [2] 61 fb [2] 7f e6 [2] 7d e7 [2] 66 e1 [2] 7a e6 [2] 66 c9 }

  condition:
    any of them
}