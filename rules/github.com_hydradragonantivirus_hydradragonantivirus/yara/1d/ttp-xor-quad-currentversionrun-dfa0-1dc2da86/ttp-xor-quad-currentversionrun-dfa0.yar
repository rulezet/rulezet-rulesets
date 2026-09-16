rule TTP_XOR_QUAD_CurrentVersionRun_dfa0 {
  strings:
    $key_dfa0 = { 8c cf [2] a8 c1 [2] 83 ed [2] ad cf [2] b9 d4 [2] b6 ce [2] a8 d3 [2] aa d2 [2] b1 d4 [2] ad d3 [2] b1 fc }

  condition:
    any of them
}