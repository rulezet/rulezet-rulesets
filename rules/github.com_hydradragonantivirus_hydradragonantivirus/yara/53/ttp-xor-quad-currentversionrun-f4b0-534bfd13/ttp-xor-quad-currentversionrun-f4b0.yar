rule TTP_XOR_QUAD_CurrentVersionRun_f4b0 {
  strings:
    $key_f4b0 = { a7 df [2] 83 d1 [2] a8 fd [2] 86 df [2] 92 c4 [2] 9d de [2] 83 c3 [2] 81 c2 [2] 9a c4 [2] 86 c3 [2] 9a ec }

  condition:
    any of them
}