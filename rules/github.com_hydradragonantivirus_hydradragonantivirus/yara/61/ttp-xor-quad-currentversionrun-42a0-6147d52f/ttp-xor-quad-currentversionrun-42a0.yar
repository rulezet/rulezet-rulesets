rule TTP_XOR_QUAD_CurrentVersionRun_42a0 {
  strings:
    $key_42a0 = { 11 cf [2] 35 c1 [2] 1e ed [2] 30 cf [2] 24 d4 [2] 2b ce [2] 35 d3 [2] 37 d2 [2] 2c d4 [2] 30 d3 [2] 2c fc }

  condition:
    any of them
}