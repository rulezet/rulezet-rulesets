rule TTP_XOR_QUAD_CurrentVersionRun_b34a {
  strings:
    $key_b34a = { e0 25 [2] c4 2b [2] ef 07 [2] c1 25 [2] d5 3e [2] da 24 [2] c4 39 [2] c6 38 [2] dd 3e [2] c1 39 [2] dd 16 }

  condition:
    any of them
}