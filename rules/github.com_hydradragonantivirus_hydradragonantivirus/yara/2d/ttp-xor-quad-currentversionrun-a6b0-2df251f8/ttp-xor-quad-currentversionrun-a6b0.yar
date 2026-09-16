rule TTP_XOR_QUAD_CurrentVersionRun_a6b0 {
  strings:
    $key_a6b0 = { f5 df [2] d1 d1 [2] fa fd [2] d4 df [2] c0 c4 [2] cf de [2] d1 c3 [2] d3 c2 [2] c8 c4 [2] d4 c3 [2] c8 ec }

  condition:
    any of them
}