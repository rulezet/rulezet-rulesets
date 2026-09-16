rule TTP_XOR_QUAD_CurrentVersionRun_b369 {
  strings:
    $key_b369 = { e0 06 [2] c4 08 [2] ef 24 [2] c1 06 [2] d5 1d [2] da 07 [2] c4 1a [2] c6 1b [2] dd 1d [2] c1 1a [2] dd 35 }

  condition:
    any of them
}