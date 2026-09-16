rule TTP_XOR_QUAD_CurrentVersionRun_d0b0 {
  strings:
    $key_d0b0 = { 83 df [2] a7 d1 [2] 8c fd [2] a2 df [2] b6 c4 [2] b9 de [2] a7 c3 [2] a5 c2 [2] be c4 [2] a2 c3 [2] be ec }

  condition:
    any of them
}