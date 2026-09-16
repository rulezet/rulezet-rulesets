rule TTP_XOR_QUAD_CurrentVersionRun_7dbd {
  strings:
    $key_7dbd = { 2e d2 [2] 0a dc [2] 21 f0 [2] 0f d2 [2] 1b c9 [2] 14 d3 [2] 0a ce [2] 08 cf [2] 13 c9 [2] 0f ce [2] 13 e1 }

  condition:
    any of them
}