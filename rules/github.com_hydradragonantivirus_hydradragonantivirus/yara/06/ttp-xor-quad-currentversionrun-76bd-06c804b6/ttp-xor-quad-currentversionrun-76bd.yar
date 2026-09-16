rule TTP_XOR_QUAD_CurrentVersionRun_76bd {
  strings:
    $key_76bd = { 25 d2 [2] 01 dc [2] 2a f0 [2] 04 d2 [2] 10 c9 [2] 1f d3 [2] 01 ce [2] 03 cf [2] 18 c9 [2] 04 ce [2] 18 e1 }

  condition:
    any of them
}