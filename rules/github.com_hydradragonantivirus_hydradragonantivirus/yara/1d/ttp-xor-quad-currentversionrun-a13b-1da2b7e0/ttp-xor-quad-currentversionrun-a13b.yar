rule TTP_XOR_QUAD_CurrentVersionRun_a13b {
  strings:
    $key_a13b = { f2 54 [2] d6 5a [2] fd 76 [2] d3 54 [2] c7 4f [2] c8 55 [2] d6 48 [2] d4 49 [2] cf 4f [2] d3 48 [2] cf 67 }

  condition:
    any of them
}