rule TTP_XOR_QUAD_CurrentVersionRun_5cb0 {
  strings:
    $key_5cb0 = { 0f df [2] 2b d1 [2] 00 fd [2] 2e df [2] 3a c4 [2] 35 de [2] 2b c3 [2] 29 c2 [2] 32 c4 [2] 2e c3 [2] 32 ec }

  condition:
    any of them
}