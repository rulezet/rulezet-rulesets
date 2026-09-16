rule TTP_XOR_QUAD_CurrentVersionRun_aba0 {
  strings:
    $key_aba0 = { f8 cf [2] dc c1 [2] f7 ed [2] d9 cf [2] cd d4 [2] c2 ce [2] dc d3 [2] de d2 [2] c5 d4 [2] d9 d3 [2] c5 fc }

  condition:
    any of them
}