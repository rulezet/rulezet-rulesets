rule TTP_XOR_QUAD_CurrentVersionRun_10a0 {
  strings:
    $key_10a0 = { 43 cf [2] 67 c1 [2] 4c ed [2] 62 cf [2] 76 d4 [2] 79 ce [2] 67 d3 [2] 65 d2 [2] 7e d4 [2] 62 d3 [2] 7e fc }

  condition:
    any of them
}