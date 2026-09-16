rule TTP_XOR_QUAD_CurrentVersionRun_a146 {
  strings:
    $key_a146 = { f2 29 [2] d6 27 [2] fd 0b [2] d3 29 [2] c7 32 [2] c8 28 [2] d6 35 [2] d4 34 [2] cf 32 [2] d3 35 [2] cf 1a }

  condition:
    any of them
}