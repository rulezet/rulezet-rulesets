rule TTP_XOR_QUAD_CurrentVersionRun_d1b0 {
  strings:
    $key_d1b0 = { 82 df [2] a6 d1 [2] 8d fd [2] a3 df [2] b7 c4 [2] b8 de [2] a6 c3 [2] a4 c2 [2] bf c4 [2] a3 c3 [2] bf ec }

  condition:
    any of them
}