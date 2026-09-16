rule TTP_XOR_QUAD_CurrentVersionRun_d4a1 {
  strings:
    $key_d4a1 = { 87 ce [2] a3 c0 [2] 88 ec [2] a6 ce [2] b2 d5 [2] bd cf [2] a3 d2 [2] a1 d3 [2] ba d5 [2] a6 d2 [2] ba fd }

  condition:
    any of them
}