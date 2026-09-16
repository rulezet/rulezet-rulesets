rule TTP_XOR_QUAD_CurrentVersionRun_a1d6 {
  strings:
    $key_a1d6 = { f2 b9 [2] d6 b7 [2] fd 9b [2] d3 b9 [2] c7 a2 [2] c8 b8 [2] d6 a5 [2] d4 a4 [2] cf a2 [2] d3 a5 [2] cf 8a }

  condition:
    any of them
}