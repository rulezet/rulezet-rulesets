rule TTP_XOR_QUAD_CurrentVersionRun_d3bd {
  strings:
    $key_d3bd = { 80 d2 [2] a4 dc [2] 8f f0 [2] a1 d2 [2] b5 c9 [2] ba d3 [2] a4 ce [2] a6 cf [2] bd c9 [2] a1 ce [2] bd e1 }

  condition:
    any of them
}