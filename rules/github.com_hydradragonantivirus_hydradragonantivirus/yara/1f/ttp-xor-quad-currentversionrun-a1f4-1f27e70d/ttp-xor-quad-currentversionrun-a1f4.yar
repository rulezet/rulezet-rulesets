rule TTP_XOR_QUAD_CurrentVersionRun_a1f4 {
  strings:
    $key_a1f4 = { f2 9b [2] d6 95 [2] fd b9 [2] d3 9b [2] c7 80 [2] c8 9a [2] d6 87 [2] d4 86 [2] cf 80 [2] d3 87 [2] cf a8 }

  condition:
    any of them
}