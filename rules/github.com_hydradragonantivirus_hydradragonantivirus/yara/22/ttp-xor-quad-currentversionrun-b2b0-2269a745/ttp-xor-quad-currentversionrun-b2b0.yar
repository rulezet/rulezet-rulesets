rule TTP_XOR_QUAD_CurrentVersionRun_b2b0 {
  strings:
    $key_b2b0 = { e1 df [2] c5 d1 [2] ee fd [2] c0 df [2] d4 c4 [2] db de [2] c5 c3 [2] c7 c2 [2] dc c4 [2] c0 c3 [2] dc ec }

  condition:
    any of them
}