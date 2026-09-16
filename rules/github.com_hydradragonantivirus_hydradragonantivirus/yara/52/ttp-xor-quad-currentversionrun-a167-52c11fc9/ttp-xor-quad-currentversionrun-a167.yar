rule TTP_XOR_QUAD_CurrentVersionRun_a167 {
  strings:
    $key_a167 = { f2 08 [2] d6 06 [2] fd 2a [2] d3 08 [2] c7 13 [2] c8 09 [2] d6 14 [2] d4 15 [2] cf 13 [2] d3 14 [2] cf 3b }

  condition:
    any of them
}