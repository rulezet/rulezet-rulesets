rule TTP_XOR_QUAD_CurrentVersionRun_b411 {
  strings:
    $key_b411 = { e7 7e [2] c3 70 [2] e8 5c [2] c6 7e [2] d2 65 [2] dd 7f [2] c3 62 [2] c1 63 [2] da 65 [2] c6 62 [2] da 4d }

  condition:
    any of them
}