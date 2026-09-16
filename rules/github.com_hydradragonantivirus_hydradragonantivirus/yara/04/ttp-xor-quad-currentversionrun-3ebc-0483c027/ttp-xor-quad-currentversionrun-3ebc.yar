rule TTP_XOR_QUAD_CurrentVersionRun_3ebc {
  strings:
    $key_3ebc = { 6d d3 [2] 49 dd [2] 62 f1 [2] 4c d3 [2] 58 c8 [2] 57 d2 [2] 49 cf [2] 4b ce [2] 50 c8 [2] 4c cf [2] 50 e0 }

  condition:
    any of them
}