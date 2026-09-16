rule TTP_XOR_QUAD_CurrentVersionRun_34b0 {
  strings:
    $key_34b0 = { 67 df [2] 43 d1 [2] 68 fd [2] 46 df [2] 52 c4 [2] 5d de [2] 43 c3 [2] 41 c2 [2] 5a c4 [2] 46 c3 [2] 5a ec }

  condition:
    any of them
}