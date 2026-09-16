rule TTP_XOR_QUAD_CurrentVersionRun_e3a0 {
  strings:
    $key_e3a0 = { b0 cf [2] 94 c1 [2] bf ed [2] 91 cf [2] 85 d4 [2] 8a ce [2] 94 d3 [2] 96 d2 [2] 8d d4 [2] 91 d3 [2] 8d fc }

  condition:
    any of them
}