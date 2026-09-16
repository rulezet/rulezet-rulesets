rule TTP_XOR_QUAD_CurrentVersionRun_e789 {
  strings:
    $key_e789 = { b4 e6 [2] 90 e8 [2] bb c4 [2] 95 e6 [2] 81 fd [2] 8e e7 [2] 90 fa [2] 92 fb [2] 89 fd [2] 95 fa [2] 89 d5 }

  condition:
    any of them
}