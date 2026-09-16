rule TTP_XOR_QUAD_CurrentVersionRun_33a0 {
  strings:
    $key_33a0 = { 60 cf [2] 44 c1 [2] 6f ed [2] 41 cf [2] 55 d4 [2] 5a ce [2] 44 d3 [2] 46 d2 [2] 5d d4 [2] 41 d3 [2] 5d fc }

  condition:
    any of them
}