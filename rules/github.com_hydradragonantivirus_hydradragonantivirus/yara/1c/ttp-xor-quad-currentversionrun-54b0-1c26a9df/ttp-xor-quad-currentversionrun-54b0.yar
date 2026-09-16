rule TTP_XOR_QUAD_CurrentVersionRun_54b0 {
  strings:
    $key_54b0 = { 07 df [2] 23 d1 [2] 08 fd [2] 26 df [2] 32 c4 [2] 3d de [2] 23 c3 [2] 21 c2 [2] 3a c4 [2] 26 c3 [2] 3a ec }

  condition:
    any of them
}