rule TTP_XOR_QUAD_CurrentVersionRun_a7a0 {
  strings:
    $key_a7a0 = { f4 cf [2] d0 c1 [2] fb ed [2] d5 cf [2] c1 d4 [2] ce ce [2] d0 d3 [2] d2 d2 [2] c9 d4 [2] d5 d3 [2] c9 fc }

  condition:
    any of them
}