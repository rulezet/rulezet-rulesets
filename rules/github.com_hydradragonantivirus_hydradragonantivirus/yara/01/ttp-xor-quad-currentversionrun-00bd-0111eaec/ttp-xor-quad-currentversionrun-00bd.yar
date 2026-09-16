rule TTP_XOR_QUAD_CurrentVersionRun_00bd {
  strings:
    $key_00bd = { 53 d2 [2] 77 dc [2] 5c f0 [2] 72 d2 [2] 66 c9 [2] 69 d3 [2] 77 ce [2] 75 cf [2] 6e c9 [2] 72 ce [2] 6e e1 }

  condition:
    any of them
}