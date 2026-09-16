rule TTP_XOR_QUAD_CurrentVersionRun_a3a0 {
  strings:
    $key_a3a0 = { f0 cf [2] d4 c1 [2] ff ed [2] d1 cf [2] c5 d4 [2] ca ce [2] d4 d3 [2] d6 d2 [2] cd d4 [2] d1 d3 [2] cd fc }

  condition:
    any of them
}