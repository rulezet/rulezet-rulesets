rule TTP_XOR_QUAD_CurrentVersionRun_e0a0 {
  strings:
    $key_e0a0 = { b3 cf [2] 97 c1 [2] bc ed [2] 92 cf [2] 86 d4 [2] 89 ce [2] 97 d3 [2] 95 d2 [2] 8e d4 [2] 92 d3 [2] 8e fc }

  condition:
    any of them
}