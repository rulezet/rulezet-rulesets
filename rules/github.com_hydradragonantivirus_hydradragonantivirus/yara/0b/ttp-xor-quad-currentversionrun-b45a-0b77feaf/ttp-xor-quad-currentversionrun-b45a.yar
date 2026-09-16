rule TTP_XOR_QUAD_CurrentVersionRun_b45a {
  strings:
    $key_b45a = { e7 35 [2] c3 3b [2] e8 17 [2] c6 35 [2] d2 2e [2] dd 34 [2] c3 29 [2] c1 28 [2] da 2e [2] c6 29 [2] da 06 }

  condition:
    any of them
}