rule TTP_XOR_QUAD_CurrentVersionRun_c9a1 {
  strings:
    $key_c9a1 = { 9a ce [2] be c0 [2] 95 ec [2] bb ce [2] af d5 [2] a0 cf [2] be d2 [2] bc d3 [2] a7 d5 [2] bb d2 [2] a7 fd }

  condition:
    any of them
}