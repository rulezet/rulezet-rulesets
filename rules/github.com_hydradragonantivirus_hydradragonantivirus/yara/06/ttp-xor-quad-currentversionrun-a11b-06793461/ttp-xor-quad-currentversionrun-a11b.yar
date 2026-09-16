rule TTP_XOR_QUAD_CurrentVersionRun_a11b {
  strings:
    $key_a11b = { f2 74 [2] d6 7a [2] fd 56 [2] d3 74 [2] c7 6f [2] c8 75 [2] d6 68 [2] d4 69 [2] cf 6f [2] d3 68 [2] cf 47 }

  condition:
    any of them
}