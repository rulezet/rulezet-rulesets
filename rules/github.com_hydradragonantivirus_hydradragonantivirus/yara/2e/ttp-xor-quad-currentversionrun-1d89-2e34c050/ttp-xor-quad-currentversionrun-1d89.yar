rule TTP_XOR_QUAD_CurrentVersionRun_1d89 {
  strings:
    $key_1d89 = { 4e e6 [2] 6a e8 [2] 41 c4 [2] 6f e6 [2] 7b fd [2] 74 e7 [2] 6a fa [2] 68 fb [2] 73 fd [2] 6f fa [2] 73 d5 }

  condition:
    any of them
}