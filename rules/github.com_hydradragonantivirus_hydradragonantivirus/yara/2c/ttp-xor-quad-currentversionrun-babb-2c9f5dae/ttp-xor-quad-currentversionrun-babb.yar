rule TTP_XOR_QUAD_CurrentVersionRun_babb {
  strings:
    $key_babb = { e9 d4 [2] cd da [2] e6 f6 [2] c8 d4 [2] dc cf [2] d3 d5 [2] cd c8 [2] cf c9 [2] d4 cf [2] c8 c8 [2] d4 e7 }

  condition:
    any of them
}