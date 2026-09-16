rule TTP_XOR_QUAD_CurrentVersionRun_c3b0 {
  strings:
    $key_c3b0 = { 90 df [2] b4 d1 [2] 9f fd [2] b1 df [2] a5 c4 [2] aa de [2] b4 c3 [2] b6 c2 [2] ad c4 [2] b1 c3 [2] ad ec }

  condition:
    any of them
}