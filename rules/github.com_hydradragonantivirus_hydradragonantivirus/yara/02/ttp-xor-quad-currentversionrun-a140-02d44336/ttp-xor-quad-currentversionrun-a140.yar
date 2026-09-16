rule TTP_XOR_QUAD_CurrentVersionRun_a140 {
  strings:
    $key_a140 = { f2 2f [2] d6 21 [2] fd 0d [2] d3 2f [2] c7 34 [2] c8 2e [2] d6 33 [2] d4 32 [2] cf 34 [2] d3 33 [2] cf 1c }

  condition:
    any of them
}