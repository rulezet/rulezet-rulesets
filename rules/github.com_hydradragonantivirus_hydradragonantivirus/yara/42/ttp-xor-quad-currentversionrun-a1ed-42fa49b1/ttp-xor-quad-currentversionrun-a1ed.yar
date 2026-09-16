rule TTP_XOR_QUAD_CurrentVersionRun_a1ed {
  strings:
    $key_a1ed = { f2 82 [2] d6 8c [2] fd a0 [2] d3 82 [2] c7 99 [2] c8 83 [2] d6 9e [2] d4 9f [2] cf 99 [2] d3 9e [2] cf b1 }

  condition:
    any of them
}