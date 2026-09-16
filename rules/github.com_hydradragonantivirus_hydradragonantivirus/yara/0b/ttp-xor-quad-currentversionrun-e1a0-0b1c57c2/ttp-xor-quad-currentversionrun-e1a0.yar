rule TTP_XOR_QUAD_CurrentVersionRun_e1a0 {
  strings:
    $key_e1a0 = { b2 cf [2] 96 c1 [2] bd ed [2] 93 cf [2] 87 d4 [2] 88 ce [2] 96 d3 [2] 94 d2 [2] 8f d4 [2] 93 d3 [2] 8f fc }

  condition:
    any of them
}