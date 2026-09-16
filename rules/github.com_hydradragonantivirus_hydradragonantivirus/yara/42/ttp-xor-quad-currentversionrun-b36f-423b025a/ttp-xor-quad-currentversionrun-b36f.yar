rule TTP_XOR_QUAD_CurrentVersionRun_b36f {
  strings:
    $key_b36f = { e0 00 [2] c4 0e [2] ef 22 [2] c1 00 [2] d5 1b [2] da 01 [2] c4 1c [2] c6 1d [2] dd 1b [2] c1 1c [2] dd 33 }

  condition:
    any of them
}