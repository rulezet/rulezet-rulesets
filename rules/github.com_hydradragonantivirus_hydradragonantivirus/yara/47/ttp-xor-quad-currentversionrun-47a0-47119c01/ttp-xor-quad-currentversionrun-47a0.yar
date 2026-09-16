rule TTP_XOR_QUAD_CurrentVersionRun_47a0 {
  strings:
    $key_47a0 = { 14 cf [2] 30 c1 [2] 1b ed [2] 35 cf [2] 21 d4 [2] 2e ce [2] 30 d3 [2] 32 d2 [2] 29 d4 [2] 35 d3 [2] 29 fc }

  condition:
    any of them
}