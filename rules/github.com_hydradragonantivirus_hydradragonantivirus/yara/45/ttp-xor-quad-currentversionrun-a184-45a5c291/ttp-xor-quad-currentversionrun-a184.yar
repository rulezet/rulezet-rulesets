rule TTP_XOR_QUAD_CurrentVersionRun_a184 {
  strings:
    $key_a184 = { f2 eb [2] d6 e5 [2] fd c9 [2] d3 eb [2] c7 f0 [2] c8 ea [2] d6 f7 [2] d4 f6 [2] cf f0 [2] d3 f7 [2] cf d8 }

  condition:
    any of them
}