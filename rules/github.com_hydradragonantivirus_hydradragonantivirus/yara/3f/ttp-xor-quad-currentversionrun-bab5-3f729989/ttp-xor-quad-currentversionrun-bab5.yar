rule TTP_XOR_QUAD_CurrentVersionRun_bab5 {
  strings:
    $key_bab5 = { e9 da [2] cd d4 [2] e6 f8 [2] c8 da [2] dc c1 [2] d3 db [2] cd c6 [2] cf c7 [2] d4 c1 [2] c8 c6 [2] d4 e9 }

  condition:
    any of them
}