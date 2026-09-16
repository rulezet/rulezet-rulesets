rule TTP_XOR_QUAD_CurrentVersionRun_c8a1 {
  strings:
    $key_c8a1 = { 9b ce [2] bf c0 [2] 94 ec [2] ba ce [2] ae d5 [2] a1 cf [2] bf d2 [2] bd d3 [2] a6 d5 [2] ba d2 [2] a6 fd }

  condition:
    any of them
}