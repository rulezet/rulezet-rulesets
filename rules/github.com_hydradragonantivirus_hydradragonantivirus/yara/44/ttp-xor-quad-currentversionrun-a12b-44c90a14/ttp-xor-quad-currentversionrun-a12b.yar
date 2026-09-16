rule TTP_XOR_QUAD_CurrentVersionRun_a12b {
  strings:
    $key_a12b = { f2 44 [2] d6 4a [2] fd 66 [2] d3 44 [2] c7 5f [2] c8 45 [2] d6 58 [2] d4 59 [2] cf 5f [2] d3 58 [2] cf 77 }

  condition:
    any of them
}