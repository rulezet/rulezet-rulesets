rule TTP_XOR_QUAD_CurrentVersionRun_b37c {
  strings:
    $key_b37c = { e0 13 [2] c4 1d [2] ef 31 [2] c1 13 [2] d5 08 [2] da 12 [2] c4 0f [2] c6 0e [2] dd 08 [2] c1 0f [2] dd 20 }

  condition:
    any of them
}