rule TTP_XOR_QUAD_CurrentVersionRun_d4b0 {
  strings:
    $key_d4b0 = { 87 df [2] a3 d1 [2] 88 fd [2] a6 df [2] b2 c4 [2] bd de [2] a3 c3 [2] a1 c2 [2] ba c4 [2] a6 c3 [2] ba ec }

  condition:
    any of them
}