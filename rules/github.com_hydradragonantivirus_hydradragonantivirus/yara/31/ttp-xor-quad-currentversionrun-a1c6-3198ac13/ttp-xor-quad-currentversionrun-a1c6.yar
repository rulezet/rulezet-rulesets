rule TTP_XOR_QUAD_CurrentVersionRun_a1c6 {
  strings:
    $key_a1c6 = { f2 a9 [2] d6 a7 [2] fd 8b [2] d3 a9 [2] c7 b2 [2] c8 a8 [2] d6 b5 [2] d4 b4 [2] cf b2 [2] d3 b5 [2] cf 9a }

  condition:
    any of them
}