rule TTP_XOR_QUAD_CurrentVersionRun_e4a0 {
  strings:
    $key_e4a0 = { b7 cf [2] 93 c1 [2] b8 ed [2] 96 cf [2] 82 d4 [2] 8d ce [2] 93 d3 [2] 91 d2 [2] 8a d4 [2] 96 d3 [2] 8a fc }

  condition:
    any of them
}