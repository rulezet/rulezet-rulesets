rule TTP_XOR_QUAD_CurrentVersionRun_4db0 {
  strings:
    $key_4db0 = { 1e df [2] 3a d1 [2] 11 fd [2] 3f df [2] 2b c4 [2] 24 de [2] 3a c3 [2] 38 c2 [2] 23 c4 [2] 3f c3 [2] 23 ec }

  condition:
    any of them
}