rule TTP_XOR_QUAD_CurrentVersionRun_22a0 {
  strings:
    $key_22a0 = { 71 cf [2] 55 c1 [2] 7e ed [2] 50 cf [2] 44 d4 [2] 4b ce [2] 55 d3 [2] 57 d2 [2] 4c d4 [2] 50 d3 [2] 4c fc }

  condition:
    any of them
}