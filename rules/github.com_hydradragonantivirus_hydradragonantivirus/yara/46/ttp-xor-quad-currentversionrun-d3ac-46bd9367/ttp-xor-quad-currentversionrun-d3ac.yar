rule TTP_XOR_QUAD_CurrentVersionRun_d3ac {
  strings:
    $key_d3ac = { 80 c3 [2] a4 cd [2] 8f e1 [2] a1 c3 [2] b5 d8 [2] ba c2 [2] a4 df [2] a6 de [2] bd d8 [2] a1 df [2] bd f0 }

  condition:
    any of them
}