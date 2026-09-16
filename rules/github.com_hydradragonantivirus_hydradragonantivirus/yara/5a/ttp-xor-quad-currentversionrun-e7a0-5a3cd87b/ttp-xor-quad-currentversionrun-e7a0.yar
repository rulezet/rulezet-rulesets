rule TTP_XOR_QUAD_CurrentVersionRun_e7a0 {
  strings:
    $key_e7a0 = { b4 cf [2] 90 c1 [2] bb ed [2] 95 cf [2] 81 d4 [2] 8e ce [2] 90 d3 [2] 92 d2 [2] 89 d4 [2] 95 d3 [2] 89 fc }

  condition:
    any of them
}