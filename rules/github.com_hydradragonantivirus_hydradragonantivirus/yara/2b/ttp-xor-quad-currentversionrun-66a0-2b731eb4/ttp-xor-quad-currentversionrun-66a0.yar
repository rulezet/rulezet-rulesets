rule TTP_XOR_QUAD_CurrentVersionRun_66a0 {
  strings:
    $key_66a0 = { 35 cf [2] 11 c1 [2] 3a ed [2] 14 cf [2] 00 d4 [2] 0f ce [2] 11 d3 [2] 13 d2 [2] 08 d4 [2] 14 d3 [2] 08 fc }

  condition:
    any of them
}