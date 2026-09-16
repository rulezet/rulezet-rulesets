rule TTP_XOR_QUAD_CurrentVersionRun_3895 {
  strings:
    $key_3895 = { 6b fa [2] 4f f4 [2] 64 d8 [2] 4a fa [2] 5e e1 [2] 51 fb [2] 4f e6 [2] 4d e7 [2] 56 e1 [2] 4a e6 [2] 56 c9 }

  condition:
    any of them
}