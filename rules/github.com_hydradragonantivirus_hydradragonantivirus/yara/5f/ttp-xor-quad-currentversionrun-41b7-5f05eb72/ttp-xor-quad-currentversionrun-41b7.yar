rule TTP_XOR_QUAD_CurrentVersionRun_41b7 {
  strings:
    $key_41b7 = { 12 d8 [2] 36 d6 [2] 1d fa [2] 33 d8 [2] 27 c3 [2] 28 d9 [2] 36 c4 [2] 34 c5 [2] 2f c3 [2] 33 c4 [2] 2f eb }

  condition:
    any of them
}