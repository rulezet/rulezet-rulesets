rule TTP_XOR_QUAD_CurrentVersionRun_a6a0 {
  strings:
    $key_a6a0 = { f5 cf [2] d1 c1 [2] fa ed [2] d4 cf [2] c0 d4 [2] cf ce [2] d1 d3 [2] d3 d2 [2] c8 d4 [2] d4 d3 [2] c8 fc }

  condition:
    any of them
}