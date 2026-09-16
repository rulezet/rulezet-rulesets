rule TTP_XOR_QUAD_CurrentVersionRun_b37f {
  strings:
    $key_b37f = { e0 10 [2] c4 1e [2] ef 32 [2] c1 10 [2] d5 0b [2] da 11 [2] c4 0c [2] c6 0d [2] dd 0b [2] c1 0c [2] dd 23 }

  condition:
    any of them
}