rule TTP_XOR_QUAD_CurrentVersionRun_b7a0 {
  strings:
    $key_b7a0 = { e4 cf [2] c0 c1 [2] eb ed [2] c5 cf [2] d1 d4 [2] de ce [2] c0 d3 [2] c2 d2 [2] d9 d4 [2] c5 d3 [2] d9 fc }

  condition:
    any of them
}