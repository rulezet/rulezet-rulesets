rule TTP_XOR_QUAD_CurrentVersionRun_cfa7 {
  strings:
    $key_cfa7 = { 9c c8 [2] b8 c6 [2] 93 ea [2] bd c8 [2] a9 d3 [2] a6 c9 [2] b8 d4 [2] ba d5 [2] a1 d3 [2] bd d4 [2] a1 fb }

  condition:
    any of them
}