rule TTP_XOR_QUAD_CurrentVersionRun_7889 {
  strings:
    $key_7889 = { 2b e6 [2] 0f e8 [2] 24 c4 [2] 0a e6 [2] 1e fd [2] 11 e7 [2] 0f fa [2] 0d fb [2] 16 fd [2] 0a fa [2] 16 d5 }

  condition:
    any of them
}