rule TTP_XOR_QUAD_CurrentVersionRun_b40d {
  strings:
    $key_b40d = { e7 62 [2] c3 6c [2] e8 40 [2] c6 62 [2] d2 79 [2] dd 63 [2] c3 7e [2] c1 7f [2] da 79 [2] c6 7e [2] da 51 }

  condition:
    any of them
}