rule TTP_XOR_QUAD_CurrentVersionRun_03b7 {
  strings:
    $key_03b7 = { 50 d8 [2] 74 d6 [2] 5f fa [2] 71 d8 [2] 65 c3 [2] 6a d9 [2] 74 c4 [2] 76 c5 [2] 6d c3 [2] 71 c4 [2] 6d eb }

  condition:
    any of them
}