rule TTP_XOR_QUAD_CurrentVersionRun_a1a6 {
  strings:
    $key_a1a6 = { f2 c9 [2] d6 c7 [2] fd eb [2] d3 c9 [2] c7 d2 [2] c8 c8 [2] d6 d5 [2] d4 d4 [2] cf d2 [2] d3 d5 [2] cf fa }

  condition:
    any of them
}