rule TTP_XOR_QUAD_CurrentVersionRun_40bd {
  strings:
    $key_40bd = { 13 d2 [2] 37 dc [2] 1c f0 [2] 32 d2 [2] 26 c9 [2] 29 d3 [2] 37 ce [2] 35 cf [2] 2e c9 [2] 32 ce [2] 2e e1 }

  condition:
    any of them
}