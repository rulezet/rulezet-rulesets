rule TTP_XOR_QUAD_CurrentVersionRun_a6e7 {
  strings:
    $key_a6e7 = { f5 88 [2] d1 86 [2] fa aa [2] d4 88 [2] c0 93 [2] cf 89 [2] d1 94 [2] d3 95 [2] c8 93 [2] d4 94 [2] c8 bb }

  condition:
    any of them
}