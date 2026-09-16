rule TTP_XOR_QUAD_CurrentVersionRun_4ca1 {
  strings:
    $key_4ca1 = { 1f ce [2] 3b c0 [2] 10 ec [2] 3e ce [2] 2a d5 [2] 25 cf [2] 3b d2 [2] 39 d3 [2] 22 d5 [2] 3e d2 [2] 22 fd }

  condition:
    any of them
}