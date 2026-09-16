rule TTP_XOR_QUAD_CurrentVersionRun_a169 {
  strings:
    $key_a169 = { f2 06 [2] d6 08 [2] fd 24 [2] d3 06 [2] c7 1d [2] c8 07 [2] d6 1a [2] d4 1b [2] cf 1d [2] d3 1a [2] cf 35 }

  condition:
    any of them
}