rule TTP_XOR_QUAD_CurrentVersionRun_a3b2 {
  strings:
    $key_a3b2 = { f0 dd [2] d4 d3 [2] ff ff [2] d1 dd [2] c5 c6 [2] ca dc [2] d4 c1 [2] d6 c0 [2] cd c6 [2] d1 c1 [2] cd ee }

  condition:
    any of them
}