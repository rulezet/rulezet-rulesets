rule TTP_XOR_QUAD_CurrentVersionRun_70b7 {
  strings:
    $key_70b7 = { 23 d8 [2] 07 d6 [2] 2c fa [2] 02 d8 [2] 16 c3 [2] 19 d9 [2] 07 c4 [2] 05 c5 [2] 1e c3 [2] 02 c4 [2] 1e eb }

  condition:
    any of them
}