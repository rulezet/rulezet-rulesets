rule TTP_XOR_QUAD_CurrentVersionRun_b340 {
  strings:
    $key_b340 = { e0 2f [2] c4 21 [2] ef 0d [2] c1 2f [2] d5 34 [2] da 2e [2] c4 33 [2] c6 32 [2] dd 34 [2] c1 33 [2] dd 1c }

  condition:
    any of them
}