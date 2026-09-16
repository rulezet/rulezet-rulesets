rule TTP_XOR_QUAD_CurrentVersionRun_b047 {
  strings:
    $key_b047 = { e3 28 [2] c7 26 [2] ec 0a [2] c2 28 [2] d6 33 [2] d9 29 [2] c7 34 [2] c5 35 [2] de 33 [2] c2 34 [2] de 1b }

  condition:
    any of them
}