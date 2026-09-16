rule TTP_XOR_QUAD_CurrentVersionRun_a119 {
  strings:
    $key_a119 = { f2 76 [2] d6 78 [2] fd 54 [2] d3 76 [2] c7 6d [2] c8 77 [2] d6 6a [2] d4 6b [2] cf 6d [2] d3 6a [2] cf 45 }

  condition:
    any of them
}