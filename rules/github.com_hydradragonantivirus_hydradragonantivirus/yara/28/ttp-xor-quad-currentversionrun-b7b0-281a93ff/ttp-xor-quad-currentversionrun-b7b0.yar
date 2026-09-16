rule TTP_XOR_QUAD_CurrentVersionRun_b7b0 {
  strings:
    $key_b7b0 = { e4 df [2] c0 d1 [2] eb fd [2] c5 df [2] d1 c4 [2] de de [2] c0 c3 [2] c2 c2 [2] d9 c4 [2] c5 c3 [2] d9 ec }

  condition:
    any of them
}