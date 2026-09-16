rule TTP_XOR_QUAD_CurrentVersionRun_a136 {
  strings:
    $key_a136 = { f2 59 [2] d6 57 [2] fd 7b [2] d3 59 [2] c7 42 [2] c8 58 [2] d6 45 [2] d4 44 [2] cf 42 [2] d3 45 [2] cf 6a }

  condition:
    any of them
}