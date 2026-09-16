rule TTP_XOR_QUAD_CurrentVersionRun_53bd {
  strings:
    $key_53bd = { 00 d2 [2] 24 dc [2] 0f f0 [2] 21 d2 [2] 35 c9 [2] 3a d3 [2] 24 ce [2] 26 cf [2] 3d c9 [2] 21 ce [2] 3d e1 }

  condition:
    any of them
}