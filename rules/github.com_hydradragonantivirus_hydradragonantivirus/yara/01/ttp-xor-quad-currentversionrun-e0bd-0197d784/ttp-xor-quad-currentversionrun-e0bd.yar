rule TTP_XOR_QUAD_CurrentVersionRun_e0bd {
  strings:
    $key_e0bd = { b3 d2 [2] 97 dc [2] bc f0 [2] 92 d2 [2] 86 c9 [2] 89 d3 [2] 97 ce [2] 95 cf [2] 8e c9 [2] 92 ce [2] 8e e1 }

  condition:
    any of them
}