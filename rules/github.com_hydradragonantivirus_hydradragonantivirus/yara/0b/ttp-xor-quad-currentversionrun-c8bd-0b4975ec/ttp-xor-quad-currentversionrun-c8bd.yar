rule TTP_XOR_QUAD_CurrentVersionRun_c8bd {
  strings:
    $key_c8bd = { 9b d2 [2] bf dc [2] 94 f0 [2] ba d2 [2] ae c9 [2] a1 d3 [2] bf ce [2] bd cf [2] a6 c9 [2] ba ce [2] a6 e1 }

  condition:
    any of them
}