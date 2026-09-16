rule TTP_XOR_QUAD_CurrentVersionRun_c1b1 {
  strings:
    $key_c1b1 = { 92 de [2] b6 d0 [2] 9d fc [2] b3 de [2] a7 c5 [2] a8 df [2] b6 c2 [2] b4 c3 [2] af c5 [2] b3 c2 [2] af ed }

  condition:
    any of them
}