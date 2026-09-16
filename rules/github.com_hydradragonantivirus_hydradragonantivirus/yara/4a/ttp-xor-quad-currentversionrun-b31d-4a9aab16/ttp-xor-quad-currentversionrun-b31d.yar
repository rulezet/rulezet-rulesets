rule TTP_XOR_QUAD_CurrentVersionRun_b31d {
  strings:
    $key_b31d = { e0 72 [2] c4 7c [2] ef 50 [2] c1 72 [2] d5 69 [2] da 73 [2] c4 6e [2] c6 6f [2] dd 69 [2] c1 6e [2] dd 41 }

  condition:
    any of them
}