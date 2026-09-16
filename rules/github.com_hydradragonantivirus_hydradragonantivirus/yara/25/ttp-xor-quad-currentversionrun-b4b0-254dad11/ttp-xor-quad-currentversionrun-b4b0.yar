rule TTP_XOR_QUAD_CurrentVersionRun_b4b0 {
  strings:
    $key_b4b0 = { e7 df [2] c3 d1 [2] e8 fd [2] c6 df [2] d2 c4 [2] dd de [2] c3 c3 [2] c1 c2 [2] da c4 [2] c6 c3 [2] da ec }

  condition:
    any of them
}