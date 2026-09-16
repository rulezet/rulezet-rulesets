rule TTP_XOR_QUAD_CurrentVersionRun_72a0 {
  strings:
    $key_72a0 = { 21 cf [2] 05 c1 [2] 2e ed [2] 00 cf [2] 14 d4 [2] 1b ce [2] 05 d3 [2] 07 d2 [2] 1c d4 [2] 00 d3 [2] 1c fc }

  condition:
    any of them
}