rule TTP_XOR_QUAD_CurrentVersionRun_a127 {
  strings:
    $key_a127 = { f2 48 [2] d6 46 [2] fd 6a [2] d3 48 [2] c7 53 [2] c8 49 [2] d6 54 [2] d4 55 [2] cf 53 [2] d3 54 [2] cf 7b }

  condition:
    any of them
}