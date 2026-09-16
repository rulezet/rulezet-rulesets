rule TTP_XOR_QUAD_CurrentVersionRun_a148 {
  strings:
    $key_a148 = { f2 27 [2] d6 29 [2] fd 05 [2] d3 27 [2] c7 3c [2] c8 26 [2] d6 3b [2] d4 3a [2] cf 3c [2] d3 3b [2] cf 14 }

  condition:
    any of them
}