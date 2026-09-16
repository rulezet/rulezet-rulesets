rule TTP_XOR_QUAD_CurrentVersionRun_53b0 {
  strings:
    $key_53b0 = { 00 df [2] 24 d1 [2] 0f fd [2] 21 df [2] 35 c4 [2] 3a de [2] 24 c3 [2] 26 c2 [2] 3d c4 [2] 21 c3 [2] 3d ec }

  condition:
    any of them
}