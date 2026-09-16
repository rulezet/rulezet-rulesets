rule TTP_XOR_QUAD_CurrentVersionRun_03bd {
  strings:
    $key_03bd = { 50 d2 [2] 74 dc [2] 5f f0 [2] 71 d2 [2] 65 c9 [2] 6a d3 [2] 74 ce [2] 76 cf [2] 6d c9 [2] 71 ce [2] 6d e1 }

  condition:
    any of them
}