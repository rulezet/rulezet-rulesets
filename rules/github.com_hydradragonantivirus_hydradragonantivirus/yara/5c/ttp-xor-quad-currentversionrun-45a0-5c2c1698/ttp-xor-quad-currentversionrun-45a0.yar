rule TTP_XOR_QUAD_CurrentVersionRun_45a0 {
  strings:
    $key_45a0 = { 16 cf [2] 32 c1 [2] 19 ed [2] 37 cf [2] 23 d4 [2] 2c ce [2] 32 d3 [2] 30 d2 [2] 2b d4 [2] 37 d3 [2] 2b fc }

  condition:
    any of them
}