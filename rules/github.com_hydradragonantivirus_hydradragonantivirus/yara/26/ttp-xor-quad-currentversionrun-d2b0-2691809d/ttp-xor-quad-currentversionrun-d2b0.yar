rule TTP_XOR_QUAD_CurrentVersionRun_d2b0 {
  strings:
    $key_d2b0 = { 81 df [2] a5 d1 [2] 8e fd [2] a0 df [2] b4 c4 [2] bb de [2] a5 c3 [2] a7 c2 [2] bc c4 [2] a0 c3 [2] bc ec }

  condition:
    any of them
}