rule TTP_XOR_QUAD_CurrentVersionRun_a137 {
  strings:
    $key_a137 = { f2 58 [2] d6 56 [2] fd 7a [2] d3 58 [2] c7 43 [2] c8 59 [2] d6 44 [2] d4 45 [2] cf 43 [2] d3 44 [2] cf 6b }

  condition:
    any of them
}