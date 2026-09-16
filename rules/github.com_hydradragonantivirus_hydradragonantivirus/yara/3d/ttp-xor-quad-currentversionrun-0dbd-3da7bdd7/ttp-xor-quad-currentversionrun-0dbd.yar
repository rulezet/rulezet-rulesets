rule TTP_XOR_QUAD_CurrentVersionRun_0dbd {
  strings:
    $key_0dbd = { 5e d2 [2] 7a dc [2] 51 f0 [2] 7f d2 [2] 6b c9 [2] 64 d3 [2] 7a ce [2] 78 cf [2] 63 c9 [2] 7f ce [2] 63 e1 }

  condition:
    any of them
}