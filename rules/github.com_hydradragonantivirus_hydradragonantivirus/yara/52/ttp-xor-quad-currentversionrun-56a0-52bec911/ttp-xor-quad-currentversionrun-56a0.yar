rule TTP_XOR_QUAD_CurrentVersionRun_56a0 {
  strings:
    $key_56a0 = { 05 cf [2] 21 c1 [2] 0a ed [2] 24 cf [2] 30 d4 [2] 3f ce [2] 21 d3 [2] 23 d2 [2] 38 d4 [2] 24 d3 [2] 38 fc }

  condition:
    any of them
}