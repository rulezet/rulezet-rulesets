rule TTP_XOR_QUAD_CurrentVersionRun_b472 {
  strings:
    $key_b472 = { e7 1d [2] c3 13 [2] e8 3f [2] c6 1d [2] d2 06 [2] dd 1c [2] c3 01 [2] c1 00 [2] da 06 [2] c6 01 [2] da 2e }

  condition:
    any of them
}