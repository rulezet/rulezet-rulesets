rule TTP_XOR_QUAD_CurrentVersionRun_d3ad {
  strings:
    $key_d3ad = { 80 c2 [2] a4 cc [2] 8f e0 [2] a1 c2 [2] b5 d9 [2] ba c3 [2] a4 de [2] a6 df [2] bd d9 [2] a1 de [2] bd f1 }

  condition:
    any of them
}