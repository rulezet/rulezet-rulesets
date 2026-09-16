rule TTP_XOR_QUAD_CurrentVersionRun_07bd {
  strings:
    $key_07bd = { 54 d2 [2] 70 dc [2] 5b f0 [2] 75 d2 [2] 61 c9 [2] 6e d3 [2] 70 ce [2] 72 cf [2] 69 c9 [2] 75 ce [2] 69 e1 }

  condition:
    any of them
}