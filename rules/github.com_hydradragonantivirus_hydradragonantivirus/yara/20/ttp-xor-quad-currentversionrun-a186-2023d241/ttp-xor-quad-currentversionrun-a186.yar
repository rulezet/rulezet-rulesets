rule TTP_XOR_QUAD_CurrentVersionRun_a186 {
  strings:
    $key_a186 = { f2 e9 [2] d6 e7 [2] fd cb [2] d3 e9 [2] c7 f2 [2] c8 e8 [2] d6 f5 [2] d4 f4 [2] cf f2 [2] d3 f5 [2] cf da }

  condition:
    any of them
}