rule TTP_XOR_QUAD_CurrentVersionRun_febd {
  strings:
    $key_febd = { ad d2 [2] 89 dc [2] a2 f0 [2] 8c d2 [2] 98 c9 [2] 97 d3 [2] 89 ce [2] 8b cf [2] 90 c9 [2] 8c ce [2] 90 e1 }

  condition:
    any of them
}