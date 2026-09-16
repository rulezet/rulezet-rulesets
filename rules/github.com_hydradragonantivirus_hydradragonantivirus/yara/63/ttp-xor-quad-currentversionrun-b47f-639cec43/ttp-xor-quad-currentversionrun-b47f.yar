rule TTP_XOR_QUAD_CurrentVersionRun_b47f {
  strings:
    $key_b47f = { e7 10 [2] c3 1e [2] e8 32 [2] c6 10 [2] d2 0b [2] dd 11 [2] c3 0c [2] c1 0d [2] da 0b [2] c6 0c [2] da 23 }

  condition:
    any of them
}