rule TTP_XOR_QUAD_CurrentVersionRun_cfa0 {
  strings:
    $key_cfa0 = { 9c cf [2] b8 c1 [2] 93 ed [2] bd cf [2] a9 d4 [2] a6 ce [2] b8 d3 [2] ba d2 [2] a1 d4 [2] bd d3 [2] a1 fc }

  condition:
    any of them
}