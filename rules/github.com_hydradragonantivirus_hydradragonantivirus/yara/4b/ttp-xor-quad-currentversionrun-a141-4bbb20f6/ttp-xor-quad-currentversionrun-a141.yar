rule TTP_XOR_QUAD_CurrentVersionRun_a141 {
  strings:
    $key_a141 = { f2 2e [2] d6 20 [2] fd 0c [2] d3 2e [2] c7 35 [2] c8 2f [2] d6 32 [2] d4 33 [2] cf 35 [2] d3 32 [2] cf 1d }

  condition:
    any of them
}