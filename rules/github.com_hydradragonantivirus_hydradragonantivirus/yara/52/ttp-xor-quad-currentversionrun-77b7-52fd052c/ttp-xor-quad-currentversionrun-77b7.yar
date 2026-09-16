rule TTP_XOR_QUAD_CurrentVersionRun_77b7 {
  strings:
    $key_77b7 = { 24 d8 [2] 00 d6 [2] 2b fa [2] 05 d8 [2] 11 c3 [2] 1e d9 [2] 00 c4 [2] 02 c5 [2] 19 c3 [2] 05 c4 [2] 19 eb }

  condition:
    any of them
}