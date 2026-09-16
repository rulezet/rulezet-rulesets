rule TTP_XOR_QUAD_CurrentVersionRun_a1b0 {
  strings:
    $key_a1b0 = { f2 df [2] d6 d1 [2] fd fd [2] d3 df [2] c7 c4 [2] c8 de [2] d6 c3 [2] d4 c2 [2] cf c4 [2] d3 c3 [2] cf ec }

  condition:
    any of them
}