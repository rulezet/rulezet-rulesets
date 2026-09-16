rule TTP_XOR_QUAD_CurrentVersionRun_7ebc {
  strings:
    $key_7ebc = { 2d d3 [2] 09 dd [2] 22 f1 [2] 0c d3 [2] 18 c8 [2] 17 d2 [2] 09 cf [2] 0b ce [2] 10 c8 [2] 0c cf [2] 10 e0 }

  condition:
    any of them
}