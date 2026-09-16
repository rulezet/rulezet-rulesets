rule TTP_XOR_QUAD_CurrentVersionRun_f1bd {
  strings:
    $key_f1bd = { a2 d2 [2] 86 dc [2] ad f0 [2] 83 d2 [2] 97 c9 [2] 98 d3 [2] 86 ce [2] 84 cf [2] 9f c9 [2] 83 ce [2] 9f e1 }

  condition:
    any of them
}