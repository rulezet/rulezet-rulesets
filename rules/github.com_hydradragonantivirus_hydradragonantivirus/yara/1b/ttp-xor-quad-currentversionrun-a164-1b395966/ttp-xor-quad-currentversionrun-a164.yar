rule TTP_XOR_QUAD_CurrentVersionRun_a164 {
  strings:
    $key_a164 = { f2 0b [2] d6 05 [2] fd 29 [2] d3 0b [2] c7 10 [2] c8 0a [2] d6 17 [2] d4 16 [2] cf 10 [2] d3 17 [2] cf 38 }

  condition:
    any of them
}