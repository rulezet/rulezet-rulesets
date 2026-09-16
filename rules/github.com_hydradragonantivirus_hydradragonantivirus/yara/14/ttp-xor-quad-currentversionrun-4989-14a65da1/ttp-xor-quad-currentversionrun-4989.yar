rule TTP_XOR_QUAD_CurrentVersionRun_4989 {
  strings:
    $key_4989 = { 1a e6 [2] 3e e8 [2] 15 c4 [2] 3b e6 [2] 2f fd [2] 20 e7 [2] 3e fa [2] 3c fb [2] 27 fd [2] 3b fa [2] 27 d5 }

  condition:
    any of them
}