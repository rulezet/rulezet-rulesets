rule TTP_XOR_QUAD_CurrentVersionRun_b30a {
  strings:
    $key_b30a = { e0 65 [2] c4 6b [2] ef 47 [2] c1 65 [2] d5 7e [2] da 64 [2] c4 79 [2] c6 78 [2] dd 7e [2] c1 79 [2] dd 56 }

  condition:
    any of them
}