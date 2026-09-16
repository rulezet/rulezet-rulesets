rule TTP_XOR_QUAD_CurrentVersionRun_63b7 {
  strings:
    $key_63b7 = { 30 d8 [2] 14 d6 [2] 3f fa [2] 11 d8 [2] 05 c3 [2] 0a d9 [2] 14 c4 [2] 16 c5 [2] 0d c3 [2] 11 c4 [2] 0d eb }

  condition:
    any of them
}