rule TTP_XOR_QUAD_CurrentVersionRun_bfbc {
  strings:
    $key_bfbc = { ec d3 [2] c8 dd [2] e3 f1 [2] cd d3 [2] d9 c8 [2] d6 d2 [2] c8 cf [2] ca ce [2] d1 c8 [2] cd cf [2] d1 e0 }

  condition:
    any of them
}