rule TTP_XOR_QUAD_CurrentVersionRun_d3b0 {
  strings:
    $key_d3b0 = { 80 df [2] a4 d1 [2] 8f fd [2] a1 df [2] b5 c4 [2] ba de [2] a4 c3 [2] a6 c2 [2] bd c4 [2] a1 c3 [2] bd ec }

  condition:
    any of them
}