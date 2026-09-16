rule TTP_XOR_QUAD_CurrentVersionRun_b37a {
  strings:
    $key_b37a = { e0 15 [2] c4 1b [2] ef 37 [2] c1 15 [2] d5 0e [2] da 14 [2] c4 09 [2] c6 08 [2] dd 0e [2] c1 09 [2] dd 26 }

  condition:
    any of them
}