rule TTP_XOR_QUAD_CurrentVersionRun_a0c8 {
  strings:
    $key_a0c8 = { f3 a7 [2] d7 a9 [2] fc 85 [2] d2 a7 [2] c6 bc [2] c9 a6 [2] d7 bb [2] d5 ba [2] ce bc [2] d2 bb [2] ce 94 }

  condition:
    any of them
}