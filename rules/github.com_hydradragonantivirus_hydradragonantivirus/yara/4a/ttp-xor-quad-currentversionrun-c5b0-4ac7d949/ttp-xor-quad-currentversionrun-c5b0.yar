rule TTP_XOR_QUAD_CurrentVersionRun_c5b0 {
  strings:
    $key_c5b0 = { 96 df [2] b2 d1 [2] 99 fd [2] b7 df [2] a3 c4 [2] ac de [2] b2 c3 [2] b0 c2 [2] ab c4 [2] b7 c3 [2] ab ec }

  condition:
    any of them
}