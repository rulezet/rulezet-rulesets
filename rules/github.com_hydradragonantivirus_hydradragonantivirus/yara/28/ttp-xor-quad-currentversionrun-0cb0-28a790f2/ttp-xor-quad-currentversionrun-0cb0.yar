rule TTP_XOR_QUAD_CurrentVersionRun_0cb0 {
  strings:
    $key_0cb0 = { 5f df [2] 7b d1 [2] 50 fd [2] 7e df [2] 6a c4 [2] 65 de [2] 7b c3 [2] 79 c2 [2] 62 c4 [2] 7e c3 [2] 62 ec }

  condition:
    any of them
}