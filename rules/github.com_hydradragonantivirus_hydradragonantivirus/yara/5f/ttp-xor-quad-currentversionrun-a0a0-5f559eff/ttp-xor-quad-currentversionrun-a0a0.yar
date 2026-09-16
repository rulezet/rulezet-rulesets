rule TTP_XOR_QUAD_CurrentVersionRun_a0a0 {
  strings:
    $key_a0a0 = { f3 cf [2] d7 c1 [2] fc ed [2] d2 cf [2] c6 d4 [2] c9 ce [2] d7 d3 [2] d5 d2 [2] ce d4 [2] d2 d3 [2] ce fc }

  condition:
    any of them
}