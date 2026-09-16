rule TTP_XOR_QUAD_CurrentVersionRun_b8a1 {
  strings:
    $key_b8a1 = { eb ce [2] cf c0 [2] e4 ec [2] ca ce [2] de d5 [2] d1 cf [2] cf d2 [2] cd d3 [2] d6 d5 [2] ca d2 [2] d6 fd }

  condition:
    any of them
}