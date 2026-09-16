rule TTP_XOR_QUAD_CurrentVersionRun_a1e4 {
  strings:
    $key_a1e4 = { f2 8b [2] d6 85 [2] fd a9 [2] d3 8b [2] c7 90 [2] c8 8a [2] d6 97 [2] d4 96 [2] cf 90 [2] d3 97 [2] cf b8 }

  condition:
    any of them
}