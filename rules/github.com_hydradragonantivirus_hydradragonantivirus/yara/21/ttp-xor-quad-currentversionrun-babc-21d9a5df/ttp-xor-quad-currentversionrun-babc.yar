rule TTP_XOR_QUAD_CurrentVersionRun_babc {
  strings:
    $key_babc = { e9 d3 [2] cd dd [2] e6 f1 [2] c8 d3 [2] dc c8 [2] d3 d2 [2] cd cf [2] cf ce [2] d4 c8 [2] c8 cf [2] d4 e0 }

  condition:
    any of them
}