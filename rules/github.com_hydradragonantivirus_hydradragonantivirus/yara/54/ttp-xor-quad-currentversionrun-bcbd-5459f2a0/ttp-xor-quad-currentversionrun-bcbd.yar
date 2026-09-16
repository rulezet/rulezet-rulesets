rule TTP_XOR_QUAD_CurrentVersionRun_bcbd {
  strings:
    $key_bcbd = { ef d2 [2] cb dc [2] e0 f0 [2] ce d2 [2] da c9 [2] d5 d3 [2] cb ce [2] c9 cf [2] d2 c9 [2] ce ce [2] d2 e1 }

  condition:
    any of them
}