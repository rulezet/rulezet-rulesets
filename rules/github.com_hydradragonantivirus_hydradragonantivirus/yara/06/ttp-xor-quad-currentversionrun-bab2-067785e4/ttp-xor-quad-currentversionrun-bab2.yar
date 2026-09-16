rule TTP_XOR_QUAD_CurrentVersionRun_bab2 {
  strings:
    $key_bab2 = { e9 dd [2] cd d3 [2] e6 ff [2] c8 dd [2] dc c6 [2] d3 dc [2] cd c1 [2] cf c0 [2] d4 c6 [2] c8 c1 [2] d4 ee }

  condition:
    any of them
}