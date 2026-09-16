rule TTP_XOR_QUAD_CurrentVersionRun_7cb0 {
  strings:
    $key_7cb0 = { 2f df [2] 0b d1 [2] 20 fd [2] 0e df [2] 1a c4 [2] 15 de [2] 0b c3 [2] 09 c2 [2] 12 c4 [2] 0e c3 [2] 12 ec }

  condition:
    any of them
}