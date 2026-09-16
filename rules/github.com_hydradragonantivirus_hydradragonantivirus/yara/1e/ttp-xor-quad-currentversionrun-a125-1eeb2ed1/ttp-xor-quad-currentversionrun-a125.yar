rule TTP_XOR_QUAD_CurrentVersionRun_a125 {
  strings:
    $key_a125 = { f2 4a [2] d6 44 [2] fd 68 [2] d3 4a [2] c7 51 [2] c8 4b [2] d6 56 [2] d4 57 [2] cf 51 [2] d3 56 [2] cf 79 }

  condition:
    any of them
}