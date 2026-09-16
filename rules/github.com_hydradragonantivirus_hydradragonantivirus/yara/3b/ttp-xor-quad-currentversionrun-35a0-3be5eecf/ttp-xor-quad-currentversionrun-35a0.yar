rule TTP_XOR_QUAD_CurrentVersionRun_35a0 {
  strings:
    $key_35a0 = { 66 cf [2] 42 c1 [2] 69 ed [2] 47 cf [2] 53 d4 [2] 5c ce [2] 42 d3 [2] 40 d2 [2] 5b d4 [2] 47 d3 [2] 5b fc }

  condition:
    any of them
}