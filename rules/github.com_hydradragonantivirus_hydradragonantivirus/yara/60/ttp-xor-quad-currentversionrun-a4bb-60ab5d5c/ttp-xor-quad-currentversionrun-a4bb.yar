rule TTP_XOR_QUAD_CurrentVersionRun_a4bb {
  strings:
    $key_a4bb = { f7 d4 [2] d3 da [2] f8 f6 [2] d6 d4 [2] c2 cf [2] cd d5 [2] d3 c8 [2] d1 c9 [2] ca cf [2] d6 c8 [2] ca e7 }

  condition:
    any of them
}