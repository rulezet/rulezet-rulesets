rule TTP_XOR_QUAD_CurrentVersionRun_baa8 {
  strings:
    $key_baa8 = { e9 c7 [2] cd c9 [2] e6 e5 [2] c8 c7 [2] dc dc [2] d3 c6 [2] cd db [2] cf da [2] d4 dc [2] c8 db [2] d4 f4 }

  condition:
    any of them
}