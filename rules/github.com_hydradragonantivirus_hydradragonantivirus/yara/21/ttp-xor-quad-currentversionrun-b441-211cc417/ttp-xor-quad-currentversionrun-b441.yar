rule TTP_XOR_QUAD_CurrentVersionRun_b441 {
  strings:
    $key_b441 = { e7 2e [2] c3 20 [2] e8 0c [2] c6 2e [2] d2 35 [2] dd 2f [2] c3 32 [2] c1 33 [2] da 35 [2] c6 32 [2] da 1d }

  condition:
    any of them
}