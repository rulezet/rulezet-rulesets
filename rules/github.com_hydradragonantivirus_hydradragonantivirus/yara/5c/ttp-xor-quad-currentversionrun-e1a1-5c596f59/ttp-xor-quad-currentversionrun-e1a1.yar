rule TTP_XOR_QUAD_CurrentVersionRun_e1a1 {
  strings:
    $key_e1a1 = { b2 ce [2] 96 c0 [2] bd ec [2] 93 ce [2] 87 d5 [2] 88 cf [2] 96 d2 [2] 94 d3 [2] 8f d5 [2] 93 d2 [2] 8f fd }

  condition:
    any of them
}