rule TTP_XOR_QUAD_CurrentVersionRun_baa1 {
  strings:
    $key_baa1 = { e9 ce [2] cd c0 [2] e6 ec [2] c8 ce [2] dc d5 [2] d3 cf [2] cd d2 [2] cf d3 [2] d4 d5 [2] c8 d2 [2] d4 fd }

  condition:
    any of them
}