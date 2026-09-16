rule TTP_XOR_QUAD_CurrentVersionRun_a185 {
  strings:
    $key_a185 = { f2 ea [2] d6 e4 [2] fd c8 [2] d3 ea [2] c7 f1 [2] c8 eb [2] d6 f6 [2] d4 f7 [2] cf f1 [2] d3 f6 [2] cf d9 }

  condition:
    any of them
}