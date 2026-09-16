rule TTP_XOR_QUAD_CurrentVersionRun_4ebc {
  strings:
    $key_4ebc = { 1d d3 [2] 39 dd [2] 12 f1 [2] 3c d3 [2] 28 c8 [2] 27 d2 [2] 39 cf [2] 3b ce [2] 20 c8 [2] 3c cf [2] 20 e0 }

  condition:
    any of them
}