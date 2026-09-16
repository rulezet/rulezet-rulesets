rule TTP_XOR_QUAD_CurrentVersionRun_d5a1 {
  strings:
    $key_d5a1 = { 86 ce [2] a2 c0 [2] 89 ec [2] a7 ce [2] b3 d5 [2] bc cf [2] a2 d2 [2] a0 d3 [2] bb d5 [2] a7 d2 [2] bb fd }

  condition:
    any of them
}