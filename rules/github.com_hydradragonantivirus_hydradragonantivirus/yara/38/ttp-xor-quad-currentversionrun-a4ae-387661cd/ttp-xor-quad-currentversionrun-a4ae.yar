rule TTP_XOR_QUAD_CurrentVersionRun_a4ae {
  strings:
    $key_a4ae = { f7 c1 [2] d3 cf [2] f8 e3 [2] d6 c1 [2] c2 da [2] cd c0 [2] d3 dd [2] d1 dc [2] ca da [2] d6 dd [2] ca f2 }

  condition:
    any of them
}