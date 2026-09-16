rule TTP_XOR_QUAD_CurrentVersionRun_a175 {
  strings:
    $key_a175 = { f2 1a [2] d6 14 [2] fd 38 [2] d3 1a [2] c7 01 [2] c8 1b [2] d6 06 [2] d4 07 [2] cf 01 [2] d3 06 [2] cf 29 }

  condition:
    any of them
}