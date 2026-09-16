rule TTP_XOR_QUAD_CurrentVersionRun_55a0 {
  strings:
    $key_55a0 = { 06 cf [2] 22 c1 [2] 09 ed [2] 27 cf [2] 33 d4 [2] 3c ce [2] 22 d3 [2] 20 d2 [2] 3b d4 [2] 27 d3 [2] 3b fc }

  condition:
    any of them
}