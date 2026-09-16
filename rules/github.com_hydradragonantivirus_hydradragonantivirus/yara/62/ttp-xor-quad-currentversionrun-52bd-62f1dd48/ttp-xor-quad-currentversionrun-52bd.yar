rule TTP_XOR_QUAD_CurrentVersionRun_52bd {
  strings:
    $key_52bd = { 01 d2 [2] 25 dc [2] 0e f0 [2] 20 d2 [2] 34 c9 [2] 3b d3 [2] 25 ce [2] 27 cf [2] 3c c9 [2] 20 ce [2] 3c e1 }

  condition:
    any of them
}