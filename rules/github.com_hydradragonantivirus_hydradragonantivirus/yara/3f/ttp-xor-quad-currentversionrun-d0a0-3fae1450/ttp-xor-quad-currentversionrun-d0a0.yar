rule TTP_XOR_QUAD_CurrentVersionRun_d0a0 {
  strings:
    $key_d0a0 = { 83 cf [2] a7 c1 [2] 8c ed [2] a2 cf [2] b6 d4 [2] b9 ce [2] a7 d3 [2] a5 d2 [2] be d4 [2] a2 d3 [2] be fc }

  condition:
    any of them
}