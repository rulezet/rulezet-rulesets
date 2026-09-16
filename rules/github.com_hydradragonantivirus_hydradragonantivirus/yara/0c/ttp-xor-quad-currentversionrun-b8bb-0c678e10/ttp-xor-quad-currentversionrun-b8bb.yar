rule TTP_XOR_QUAD_CurrentVersionRun_b8bb {
  strings:
    $key_b8bb = { eb d4 [2] cf da [2] e4 f6 [2] ca d4 [2] de cf [2] d1 d5 [2] cf c8 [2] cd c9 [2] d6 cf [2] ca c8 [2] d6 e7 }

  condition:
    any of them
}