rule TTP_XOR_QUAD_CurrentVersionRun_baa0 {
  strings:
    $key_baa0 = { e9 cf [2] cd c1 [2] e6 ed [2] c8 cf [2] dc d4 [2] d3 ce [2] cd d3 [2] cf d2 [2] d4 d4 [2] c8 d3 [2] d4 fc }

  condition:
    any of them
}