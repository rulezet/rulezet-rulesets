rule TTP_XOR_QUAD_CurrentVersionRun_b0bd {
  strings:
    $key_b0bd = { e3 d2 [2] c7 dc [2] ec f0 [2] c2 d2 [2] d6 c9 [2] d9 d3 [2] c7 ce [2] c5 cf [2] de c9 [2] c2 ce [2] de e1 }

  condition:
    any of them
}