rule TTP_XOR_QUAD_CurrentVersionRun_46a0 {
  strings:
    $key_46a0 = { 15 cf [2] 31 c1 [2] 1a ed [2] 34 cf [2] 20 d4 [2] 2f ce [2] 31 d3 [2] 33 d2 [2] 28 d4 [2] 34 d3 [2] 28 fc }

  condition:
    any of them
}