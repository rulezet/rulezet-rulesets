rule TTP_XOR_QUAD_CurrentVersionRun_23bd {
  strings:
    $key_23bd = { 70 d2 [2] 54 dc [2] 7f f0 [2] 51 d2 [2] 45 c9 [2] 4a d3 [2] 54 ce [2] 56 cf [2] 4d c9 [2] 51 ce [2] 4d e1 }

  condition:
    any of them
}