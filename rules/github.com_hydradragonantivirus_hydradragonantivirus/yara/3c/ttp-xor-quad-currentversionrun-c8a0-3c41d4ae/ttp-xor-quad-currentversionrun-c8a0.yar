rule TTP_XOR_QUAD_CurrentVersionRun_c8a0 {
  strings:
    $key_c8a0 = { 9b cf [2] bf c1 [2] 94 ed [2] ba cf [2] ae d4 [2] a1 ce [2] bf d3 [2] bd d2 [2] a6 d4 [2] ba d3 [2] a6 fc }

  condition:
    any of them
}