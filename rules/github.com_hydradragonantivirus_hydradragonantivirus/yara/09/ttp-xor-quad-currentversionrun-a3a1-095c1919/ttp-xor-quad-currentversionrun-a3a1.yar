rule TTP_XOR_QUAD_CurrentVersionRun_a3a1 {
  strings:
    $key_a3a1 = { f0 ce [2] d4 c0 [2] ff ec [2] d1 ce [2] c5 d5 [2] ca cf [2] d4 d2 [2] d6 d3 [2] cd d5 [2] d1 d2 [2] cd fd }

  condition:
    any of them
}