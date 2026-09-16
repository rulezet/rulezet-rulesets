rule TTP_XOR_QUAD_CurrentVersionRun_d7b0 {
  strings:
    $key_d7b0 = { 84 df [2] a0 d1 [2] 8b fd [2] a5 df [2] b1 c4 [2] be de [2] a0 c3 [2] a2 c2 [2] b9 c4 [2] a5 c3 [2] b9 ec }

  condition:
    any of them
}