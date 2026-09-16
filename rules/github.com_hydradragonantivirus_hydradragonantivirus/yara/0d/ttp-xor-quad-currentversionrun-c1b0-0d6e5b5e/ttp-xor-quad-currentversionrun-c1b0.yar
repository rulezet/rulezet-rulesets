rule TTP_XOR_QUAD_CurrentVersionRun_c1b0 {
  strings:
    $key_c1b0 = { 92 df [2] b6 d1 [2] 9d fd [2] b3 df [2] a7 c4 [2] a8 de [2] b6 c3 [2] b4 c2 [2] af c4 [2] b3 c3 [2] af ec }

  condition:
    any of them
}