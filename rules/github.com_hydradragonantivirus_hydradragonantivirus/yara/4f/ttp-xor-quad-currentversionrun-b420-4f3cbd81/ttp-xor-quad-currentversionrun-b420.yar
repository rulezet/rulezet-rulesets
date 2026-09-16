rule TTP_XOR_QUAD_CurrentVersionRun_b420 {
  strings:
    $key_b420 = { e7 4f [2] c3 41 [2] e8 6d [2] c6 4f [2] d2 54 [2] dd 4e [2] c3 53 [2] c1 52 [2] da 54 [2] c6 53 [2] da 7c }

  condition:
    any of them
}