rule TTP_XOR_QUAD_CurrentVersionRun_a0b0 {
  strings:
    $key_a0b0 = { f3 df [2] d7 d1 [2] fc fd [2] d2 df [2] c6 c4 [2] c9 de [2] d7 c3 [2] d5 c2 [2] ce c4 [2] d2 c3 [2] ce ec }

  condition:
    any of them
}