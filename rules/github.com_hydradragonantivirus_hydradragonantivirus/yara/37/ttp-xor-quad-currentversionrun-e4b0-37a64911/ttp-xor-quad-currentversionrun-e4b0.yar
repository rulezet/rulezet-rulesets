rule TTP_XOR_QUAD_CurrentVersionRun_e4b0 {
  strings:
    $key_e4b0 = { b7 df [2] 93 d1 [2] b8 fd [2] 96 df [2] 82 c4 [2] 8d de [2] 93 c3 [2] 91 c2 [2] 8a c4 [2] 96 c3 [2] 8a ec }

  condition:
    any of them
}