rule TTP_XOR_QUAD_CurrentVersionRun_6d89 {
  strings:
    $key_6d89 = { 3e e6 [2] 1a e8 [2] 31 c4 [2] 1f e6 [2] 0b fd [2] 04 e7 [2] 1a fa [2] 18 fb [2] 03 fd [2] 1f fa [2] 03 d5 }

  condition:
    any of them
}