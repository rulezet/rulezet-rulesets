rule TTP_XOR_QUAD_CurrentVersionRun_10bd {
  strings:
    $key_10bd = { 43 d2 [2] 67 dc [2] 4c f0 [2] 62 d2 [2] 76 c9 [2] 79 d3 [2] 67 ce [2] 65 cf [2] 7e c9 [2] 62 ce [2] 7e e1 }

  condition:
    any of them
}