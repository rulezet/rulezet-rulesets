rule TTP_XOR_QUAD_CurrentVersionRun_a14e {
  strings:
    $key_a14e = { f2 21 [2] d6 2f [2] fd 03 [2] d3 21 [2] c7 3a [2] c8 20 [2] d6 3d [2] d4 3c [2] cf 3a [2] d3 3d [2] cf 12 }

  condition:
    any of them
}