rule TTP_XOR_QUAD_CurrentVersionRun_6889 {
  strings:
    $key_6889 = { 3b e6 [2] 1f e8 [2] 34 c4 [2] 1a e6 [2] 0e fd [2] 01 e7 [2] 1f fa [2] 1d fb [2] 06 fd [2] 1a fa [2] 06 d5 }

  condition:
    any of them
}