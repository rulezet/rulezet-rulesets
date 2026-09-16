rule TTP_XOR_QUAD_CurrentVersionRun_b0a1 {
  strings:
    $key_b0a1 = { e3 ce [2] c7 c0 [2] ec ec [2] c2 ce [2] d6 d5 [2] d9 cf [2] c7 d2 [2] c5 d3 [2] de d5 [2] c2 d2 [2] de fd }

  condition:
    any of them
}