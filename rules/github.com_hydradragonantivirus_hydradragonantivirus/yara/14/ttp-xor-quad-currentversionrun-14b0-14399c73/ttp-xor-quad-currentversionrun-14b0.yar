rule TTP_XOR_QUAD_CurrentVersionRun_14b0 {
  strings:
    $key_14b0 = { 47 df [2] 63 d1 [2] 48 fd [2] 66 df [2] 72 c4 [2] 7d de [2] 63 c3 [2] 61 c2 [2] 7a c4 [2] 66 c3 [2] 7a ec }

  condition:
    any of them
}