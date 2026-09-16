rule TTP_XOR_QUAD_CurrentVersionRun_a107 {
  strings:
    $key_a107 = { f2 68 [2] d6 66 [2] fd 4a [2] d3 68 [2] c7 73 [2] c8 69 [2] d6 74 [2] d4 75 [2] cf 73 [2] d3 74 [2] cf 5b }

  condition:
    any of them
}