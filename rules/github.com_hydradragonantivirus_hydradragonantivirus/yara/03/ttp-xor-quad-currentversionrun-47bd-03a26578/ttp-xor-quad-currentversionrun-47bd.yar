rule TTP_XOR_QUAD_CurrentVersionRun_47bd {
  strings:
    $key_47bd = { 14 d2 [2] 30 dc [2] 1b f0 [2] 35 d2 [2] 21 c9 [2] 2e d3 [2] 30 ce [2] 32 cf [2] 29 c9 [2] 35 ce [2] 29 e1 }

  condition:
    any of them
}