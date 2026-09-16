rule TTP_XOR_QUAD_CurrentVersionRun_d3a1 {
  strings:
    $key_d3a1 = { 80 ce [2] a4 c0 [2] 8f ec [2] a1 ce [2] b5 d5 [2] ba cf [2] a4 d2 [2] a6 d3 [2] bd d5 [2] a1 d2 [2] bd fd }

  condition:
    any of them
}