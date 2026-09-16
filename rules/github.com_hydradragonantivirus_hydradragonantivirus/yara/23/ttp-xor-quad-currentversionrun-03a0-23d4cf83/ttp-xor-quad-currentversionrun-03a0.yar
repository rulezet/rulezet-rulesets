rule TTP_XOR_QUAD_CurrentVersionRun_03a0 {
  strings:
    $key_03a0 = { 50 cf [2] 74 c1 [2] 5f ed [2] 71 cf [2] 65 d4 [2] 6a ce [2] 74 d3 [2] 76 d2 [2] 6d d4 [2] 71 d3 [2] 6d fc }

  condition:
    any of them
}