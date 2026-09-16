rule TTP_XOR_QUAD_CurrentVersionRun_b7fd {
  strings:
    $key_b7fd = { e4 92 [2] c0 9c [2] eb b0 [2] c5 92 [2] d1 89 [2] de 93 [2] c0 8e [2] c2 8f [2] d9 89 [2] c5 8e [2] d9 a1 }

  condition:
    any of them
}