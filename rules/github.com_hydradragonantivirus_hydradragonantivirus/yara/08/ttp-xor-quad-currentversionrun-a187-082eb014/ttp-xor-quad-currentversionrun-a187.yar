rule TTP_XOR_QUAD_CurrentVersionRun_a187 {
  strings:
    $key_a187 = { f2 e8 [2] d6 e6 [2] fd ca [2] d3 e8 [2] c7 f3 [2] c8 e9 [2] d6 f4 [2] d4 f5 [2] cf f3 [2] d3 f4 [2] cf db }

  condition:
    any of them
}