rule TTP_XOR_QUAD_CurrentVersionRun_2d89 {
  strings:
    $key_2d89 = { 7e e6 [2] 5a e8 [2] 71 c4 [2] 5f e6 [2] 4b fd [2] 44 e7 [2] 5a fa [2] 58 fb [2] 43 fd [2] 5f fa [2] 43 d5 }

  condition:
    any of them
}