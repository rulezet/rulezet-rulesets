rule TTP_XOR_QUAD_CurrentVersionRun_a117 {
  strings:
    $key_a117 = { f2 78 [2] d6 76 [2] fd 5a [2] d3 78 [2] c7 63 [2] c8 79 [2] d6 64 [2] d4 65 [2] cf 63 [2] d3 64 [2] cf 4b }

  condition:
    any of them
}