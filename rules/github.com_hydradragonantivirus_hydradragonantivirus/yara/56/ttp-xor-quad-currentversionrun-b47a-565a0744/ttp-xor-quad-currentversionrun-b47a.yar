rule TTP_XOR_QUAD_CurrentVersionRun_b47a {
  strings:
    $key_b47a = { e7 15 [2] c3 1b [2] e8 37 [2] c6 15 [2] d2 0e [2] dd 14 [2] c3 09 [2] c1 08 [2] da 0e [2] c6 09 [2] da 26 }

  condition:
    any of them
}