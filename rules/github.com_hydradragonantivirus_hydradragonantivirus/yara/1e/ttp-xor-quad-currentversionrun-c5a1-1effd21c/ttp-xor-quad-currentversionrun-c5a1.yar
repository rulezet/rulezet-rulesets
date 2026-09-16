rule TTP_XOR_QUAD_CurrentVersionRun_c5a1 {
  strings:
    $key_c5a1 = { 96 ce [2] b2 c0 [2] 99 ec [2] b7 ce [2] a3 d5 [2] ac cf [2] b2 d2 [2] b0 d3 [2] ab d5 [2] b7 d2 [2] ab fd }

  condition:
    any of them
}