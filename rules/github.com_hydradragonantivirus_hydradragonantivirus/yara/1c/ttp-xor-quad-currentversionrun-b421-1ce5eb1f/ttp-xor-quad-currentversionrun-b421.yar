rule TTP_XOR_QUAD_CurrentVersionRun_b421 {
  strings:
    $key_b421 = { e7 4e [2] c3 40 [2] e8 6c [2] c6 4e [2] d2 55 [2] dd 4f [2] c3 52 [2] c1 53 [2] da 55 [2] c6 52 [2] da 7d }

  condition:
    any of them
}