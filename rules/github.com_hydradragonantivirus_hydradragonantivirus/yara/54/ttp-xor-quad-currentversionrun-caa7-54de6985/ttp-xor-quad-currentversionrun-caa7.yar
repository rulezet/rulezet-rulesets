rule TTP_XOR_QUAD_CurrentVersionRun_caa7 {
  strings:
    $key_caa7 = { 99 c8 [2] bd c6 [2] 96 ea [2] b8 c8 [2] ac d3 [2] a3 c9 [2] bd d4 [2] bf d5 [2] a4 d3 [2] b8 d4 [2] a4 fb }

  condition:
    any of them
}