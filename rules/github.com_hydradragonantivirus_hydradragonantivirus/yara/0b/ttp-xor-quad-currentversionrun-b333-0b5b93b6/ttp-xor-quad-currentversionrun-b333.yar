rule TTP_XOR_QUAD_CurrentVersionRun_b333 {
  strings:
    $key_b333 = { e0 5c [2] c4 52 [2] ef 7e [2] c1 5c [2] d5 47 [2] da 5d [2] c4 40 [2] c6 41 [2] dd 47 [2] c1 40 [2] dd 6f }

  condition:
    any of them
}