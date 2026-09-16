rule TTP_XOR_QUAD_CurrentVersionRun_a174 {
  strings:
    $key_a174 = { f2 1b [2] d6 15 [2] fd 39 [2] d3 1b [2] c7 00 [2] c8 1a [2] d6 07 [2] d4 06 [2] cf 00 [2] d3 07 [2] cf 28 }

  condition:
    any of them
}