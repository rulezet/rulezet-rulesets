rule TTP_XOR_QUAD_CurrentVersionRun_d2a1 {
  strings:
    $key_d2a1 = { 81 ce [2] a5 c0 [2] 8e ec [2] a0 ce [2] b4 d5 [2] bb cf [2] a5 d2 [2] a7 d3 [2] bc d5 [2] a0 d2 [2] bc fd }

  condition:
    any of them
}