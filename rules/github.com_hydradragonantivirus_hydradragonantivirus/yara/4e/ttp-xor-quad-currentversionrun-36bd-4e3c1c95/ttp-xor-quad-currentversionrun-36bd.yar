rule TTP_XOR_QUAD_CurrentVersionRun_36bd {
  strings:
    $key_36bd = { 65 d2 [2] 41 dc [2] 6a f0 [2] 44 d2 [2] 50 c9 [2] 5f d3 [2] 41 ce [2] 43 cf [2] 58 c9 [2] 44 ce [2] 58 e1 }

  condition:
    any of them
}