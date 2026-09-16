rule TTP_XOR_QUAD_CurrentVersionRun_0789 {
  strings:
    $key_0789 = { 54 e6 [2] 70 e8 [2] 5b c4 [2] 75 e6 [2] 61 fd [2] 6e e7 [2] 70 fa [2] 72 fb [2] 69 fd [2] 75 fa [2] 69 d5 }

  condition:
    any of them
}