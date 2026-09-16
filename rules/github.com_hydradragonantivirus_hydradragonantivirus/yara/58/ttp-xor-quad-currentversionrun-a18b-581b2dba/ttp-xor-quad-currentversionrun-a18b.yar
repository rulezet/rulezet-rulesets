rule TTP_XOR_QUAD_CurrentVersionRun_a18b {
  strings:
    $key_a18b = { f2 e4 [2] d6 ea [2] fd c6 [2] d3 e4 [2] c7 ff [2] c8 e5 [2] d6 f8 [2] d4 f9 [2] cf ff [2] d3 f8 [2] cf d7 }

  condition:
    any of them
}