rule TTP_XOR_QUAD_CurrentVersionRun_a198 {
  strings:
    $key_a198 = { f2 f7 [2] d6 f9 [2] fd d5 [2] d3 f7 [2] c7 ec [2] c8 f6 [2] d6 eb [2] d4 ea [2] cf ec [2] d3 eb [2] cf c4 }

  condition:
    any of them
}