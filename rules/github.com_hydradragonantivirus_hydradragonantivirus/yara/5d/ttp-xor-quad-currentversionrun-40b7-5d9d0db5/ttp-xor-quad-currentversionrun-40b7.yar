rule TTP_XOR_QUAD_CurrentVersionRun_40b7 {
  strings:
    $key_40b7 = { 13 d8 [2] 37 d6 [2] 1c fa [2] 32 d8 [2] 26 c3 [2] 29 d9 [2] 37 c4 [2] 35 c5 [2] 2e c3 [2] 32 c4 [2] 2e eb }

  condition:
    any of them
}