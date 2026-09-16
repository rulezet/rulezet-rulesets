rule TTP_XOR_QUAD_CurrentVersionRun_73a0 {
  strings:
    $key_73a0 = { 20 cf [2] 04 c1 [2] 2f ed [2] 01 cf [2] 15 d4 [2] 1a ce [2] 04 d3 [2] 06 d2 [2] 1d d4 [2] 01 d3 [2] 1d fc }

  condition:
    any of them
}