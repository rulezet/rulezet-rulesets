rule TTP_XOR_QUAD_CurrentVersionRun_d3b4 {
  strings:
    $key_d3b4 = { 80 db [2] a4 d5 [2] 8f f9 [2] a1 db [2] b5 c0 [2] ba da [2] a4 c7 [2] a6 c6 [2] bd c0 [2] a1 c7 [2] bd e8 }

  condition:
    any of them
}