rule TTP_XOR_QUAD_CurrentVersionRun_edbd {
  strings:
    $key_edbd = { be d2 [2] 9a dc [2] b1 f0 [2] 9f d2 [2] 8b c9 [2] 84 d3 [2] 9a ce [2] 98 cf [2] 83 c9 [2] 9f ce [2] 83 e1 }

  condition:
    any of them
}