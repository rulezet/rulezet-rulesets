rule TTP_XOR_QUAD_CurrentVersionRun_bfbb {
  strings:
    $key_bfbb = { ec d4 [2] c8 da [2] e3 f6 [2] cd d4 [2] d9 cf [2] d6 d5 [2] c8 c8 [2] ca c9 [2] d1 cf [2] cd c8 [2] d1 e7 }

  condition:
    any of them
}