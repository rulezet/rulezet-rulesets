rule TTP_XOR_QUAD_CurrentVersionRun_f5a0 {
  strings:
    $key_f5a0 = { a6 cf [2] 82 c1 [2] a9 ed [2] 87 cf [2] 93 d4 [2] 9c ce [2] 82 d3 [2] 80 d2 [2] 9b d4 [2] 87 d3 [2] 9b fc }

  condition:
    any of them
}