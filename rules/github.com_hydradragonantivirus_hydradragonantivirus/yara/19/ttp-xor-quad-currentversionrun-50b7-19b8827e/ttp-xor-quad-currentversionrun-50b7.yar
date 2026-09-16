rule TTP_XOR_QUAD_CurrentVersionRun_50b7 {
  strings:
    $key_50b7 = { 03 d8 [2] 27 d6 [2] 0c fa [2] 22 d8 [2] 36 c3 [2] 39 d9 [2] 27 c4 [2] 25 c5 [2] 3e c3 [2] 22 c4 [2] 3e eb }

  condition:
    any of them
}