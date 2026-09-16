rule TTP_XOR_QUAD_CurrentVersionRun_a1e5 {
  strings:
    $key_a1e5 = { f2 8a [2] d6 84 [2] fd a8 [2] d3 8a [2] c7 91 [2] c8 8b [2] d6 96 [2] d4 97 [2] cf 91 [2] d3 96 [2] cf b9 }

  condition:
    any of them
}