rule TTP_XOR_QUAD_CurrentVersionRun_b0ed {
  strings:
    $key_b0ed = { e3 82 [2] c7 8c [2] ec a0 [2] c2 82 [2] d6 99 [2] d9 83 [2] c7 9e [2] c5 9f [2] de 99 [2] c2 9e [2] de b1 }

  condition:
    any of them
}