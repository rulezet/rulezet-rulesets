rule TTP_XOR_QUAD_CurrentVersionRun_a3bb {
  strings:
    $key_a3bb = { f0 d4 [2] d4 da [2] ff f6 [2] d1 d4 [2] c5 cf [2] ca d5 [2] d4 c8 [2] d6 c9 [2] cd cf [2] d1 c8 [2] cd e7 }

  condition:
    any of them
}