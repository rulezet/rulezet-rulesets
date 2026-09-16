rule TTP_XOR_QUAD_CurrentVersionRun_d3b5 {
  strings:
    $key_d3b5 = { 80 da [2] a4 d4 [2] 8f f8 [2] a1 da [2] b5 c1 [2] ba db [2] a4 c6 [2] a6 c7 [2] bd c1 [2] a1 c6 [2] bd e9 }

  condition:
    any of them
}