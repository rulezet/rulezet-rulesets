rule TTP_XOR_QUAD_CurrentVersionRun_febc {
  strings:
    $key_febc = { ad d3 [2] 89 dd [2] a2 f1 [2] 8c d3 [2] 98 c8 [2] 97 d2 [2] 89 cf [2] 8b ce [2] 90 c8 [2] 8c cf [2] 90 e0 }

  condition:
    any of them
}