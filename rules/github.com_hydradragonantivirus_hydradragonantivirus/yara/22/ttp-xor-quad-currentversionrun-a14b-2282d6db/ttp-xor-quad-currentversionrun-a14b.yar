rule TTP_XOR_QUAD_CurrentVersionRun_a14b {
  strings:
    $key_a14b = { f2 24 [2] d6 2a [2] fd 06 [2] d3 24 [2] c7 3f [2] c8 25 [2] d6 38 [2] d4 39 [2] cf 3f [2] d3 38 [2] cf 17 }

  condition:
    any of them
}