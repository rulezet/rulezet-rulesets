rule TTP_XOR_QUAD_CurrentVersionRun_36a0 {
  strings:
    $key_36a0 = { 65 cf [2] 41 c1 [2] 6a ed [2] 44 cf [2] 50 d4 [2] 5f ce [2] 41 d3 [2] 43 d2 [2] 58 d4 [2] 44 d3 [2] 58 fc }

  condition:
    any of them
}