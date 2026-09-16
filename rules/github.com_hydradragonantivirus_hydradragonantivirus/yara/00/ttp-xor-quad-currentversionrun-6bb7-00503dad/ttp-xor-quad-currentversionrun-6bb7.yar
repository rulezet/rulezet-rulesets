rule TTP_XOR_QUAD_CurrentVersionRun_6bb7 {
  strings:
    $key_6bb7 = { 38 d8 [2] 1c d6 [2] 37 fa [2] 19 d8 [2] 0d c3 [2] 02 d9 [2] 1c c4 [2] 1e c5 [2] 05 c3 [2] 19 c4 [2] 05 eb }

  condition:
    any of them
}