rule TTP_XOR_QUAD_CurrentVersionRun_f3a0 {
  strings:
    $key_f3a0 = { a0 cf [2] 84 c1 [2] af ed [2] 81 cf [2] 95 d4 [2] 9a ce [2] 84 d3 [2] 86 d2 [2] 9d d4 [2] 81 d3 [2] 9d fc }

  condition:
    any of them
}