rule TTP_XOR_QUAD_CurrentVersionRun_46bd {
  strings:
    $key_46bd = { 15 d2 [2] 31 dc [2] 1a f0 [2] 34 d2 [2] 20 c9 [2] 2f d3 [2] 31 ce [2] 33 cf [2] 28 c9 [2] 34 ce [2] 28 e1 }

  condition:
    any of them
}