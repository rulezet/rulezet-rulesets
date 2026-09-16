rule TTP_XOR_QUAD_CurrentVersionRun_b41d {
  strings:
    $key_b41d = { e7 72 [2] c3 7c [2] e8 50 [2] c6 72 [2] d2 69 [2] dd 73 [2] c3 6e [2] c1 6f [2] da 69 [2] c6 6e [2] da 41 }

  condition:
    any of them
}