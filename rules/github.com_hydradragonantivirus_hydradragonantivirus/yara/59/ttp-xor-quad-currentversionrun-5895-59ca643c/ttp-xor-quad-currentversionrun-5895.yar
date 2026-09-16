rule TTP_XOR_QUAD_CurrentVersionRun_5895 {
  strings:
    $key_5895 = { 0b fa [2] 2f f4 [2] 04 d8 [2] 2a fa [2] 3e e1 [2] 31 fb [2] 2f e6 [2] 2d e7 [2] 36 e1 [2] 2a e6 [2] 36 c9 }

  condition:
    any of them
}