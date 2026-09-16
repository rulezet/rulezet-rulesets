rule TTP_XOR_QUAD_CurrentVersionRun_e0a1 {
  strings:
    $key_e0a1 = { b3 ce [2] 97 c0 [2] bc ec [2] 92 ce [2] 86 d5 [2] 89 cf [2] 97 d2 [2] 95 d3 [2] 8e d5 [2] 92 d2 [2] 8e fd }

  condition:
    any of them
}