rule TTP_XOR_QUAD_CurrentVersionRun_cfd5 {
  strings:
    $key_cfd5 = { 9c ba [2] b8 b4 [2] 93 98 [2] bd ba [2] a9 a1 [2] a6 bb [2] b8 a6 [2] ba a7 [2] a1 a1 [2] bd a6 [2] a1 89 }

  condition:
    any of them
}