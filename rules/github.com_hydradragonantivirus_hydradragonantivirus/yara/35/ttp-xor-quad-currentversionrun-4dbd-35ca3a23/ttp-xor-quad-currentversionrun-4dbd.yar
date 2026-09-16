rule TTP_XOR_QUAD_CurrentVersionRun_4dbd {
  strings:
    $key_4dbd = { 1e d2 [2] 3a dc [2] 11 f0 [2] 3f d2 [2] 2b c9 [2] 24 d3 [2] 3a ce [2] 38 cf [2] 23 c9 [2] 3f ce [2] 23 e1 }

  condition:
    any of them
}