rule TTP_XOR_QUAD_CurrentVersionRun_a156 {
  strings:
    $key_a156 = { f2 39 [2] d6 37 [2] fd 1b [2] d3 39 [2] c7 22 [2] c8 38 [2] d6 25 [2] d4 24 [2] cf 22 [2] d3 25 [2] cf 0a }

  condition:
    any of them
}