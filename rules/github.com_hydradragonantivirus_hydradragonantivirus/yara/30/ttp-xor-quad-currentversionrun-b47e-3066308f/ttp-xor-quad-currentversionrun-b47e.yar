rule TTP_XOR_QUAD_CurrentVersionRun_b47e {
  strings:
    $key_b47e = { e7 11 [2] c3 1f [2] e8 33 [2] c6 11 [2] d2 0a [2] dd 10 [2] c3 0d [2] c1 0c [2] da 0a [2] c6 0d [2] da 22 }

  condition:
    any of them
}