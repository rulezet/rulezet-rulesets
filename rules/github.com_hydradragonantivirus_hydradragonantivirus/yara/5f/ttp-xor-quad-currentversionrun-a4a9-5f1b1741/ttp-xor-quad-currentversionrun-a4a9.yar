rule TTP_XOR_QUAD_CurrentVersionRun_a4a9 {
  strings:
    $key_a4a9 = { f7 c6 [2] d3 c8 [2] f8 e4 [2] d6 c6 [2] c2 dd [2] cd c7 [2] d3 da [2] d1 db [2] ca dd [2] d6 da [2] ca f5 }

  condition:
    any of them
}