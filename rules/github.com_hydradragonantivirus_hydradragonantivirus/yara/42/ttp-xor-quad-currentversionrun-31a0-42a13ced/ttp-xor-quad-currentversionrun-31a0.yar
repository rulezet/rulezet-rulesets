rule TTP_XOR_QUAD_CurrentVersionRun_31a0 {
  strings:
    $key_31a0 = { 62 cf [2] 46 c1 [2] 6d ed [2] 43 cf [2] 57 d4 [2] 58 ce [2] 46 d3 [2] 44 d2 [2] 5f d4 [2] 43 d3 [2] 5f fc }

  condition:
    any of them
}