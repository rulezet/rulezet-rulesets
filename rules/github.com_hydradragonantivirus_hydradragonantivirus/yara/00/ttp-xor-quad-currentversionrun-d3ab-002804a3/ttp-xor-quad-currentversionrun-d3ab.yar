rule TTP_XOR_QUAD_CurrentVersionRun_d3ab {
  strings:
    $key_d3ab = { 80 c4 [2] a4 ca [2] 8f e6 [2] a1 c4 [2] b5 df [2] ba c5 [2] a4 d8 [2] a6 d9 [2] bd df [2] a1 d8 [2] bd f7 }

  condition:
    any of them
}