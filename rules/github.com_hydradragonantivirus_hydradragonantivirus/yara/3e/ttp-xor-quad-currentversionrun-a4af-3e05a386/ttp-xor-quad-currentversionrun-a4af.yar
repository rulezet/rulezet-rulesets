rule TTP_XOR_QUAD_CurrentVersionRun_a4af {
  strings:
    $key_a4af = { f7 c0 [2] d3 ce [2] f8 e2 [2] d6 c0 [2] c2 db [2] cd c1 [2] d3 dc [2] d1 dd [2] ca db [2] d6 dc [2] ca f3 }

  condition:
    any of them
}