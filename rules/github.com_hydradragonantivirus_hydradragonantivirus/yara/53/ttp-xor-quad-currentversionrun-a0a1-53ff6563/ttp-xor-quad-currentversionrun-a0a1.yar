rule TTP_XOR_QUAD_CurrentVersionRun_a0a1 {
  strings:
    $key_a0a1 = { f3 ce [2] d7 c0 [2] fc ec [2] d2 ce [2] c6 d5 [2] c9 cf [2] d7 d2 [2] d5 d3 [2] ce d5 [2] d2 d2 [2] ce fd }

  condition:
    any of them
}