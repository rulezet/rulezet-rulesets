rule TTP_XOR_QUAD_CurrentVersionRun_b33f {
  strings:
    $key_b33f = { e0 50 [2] c4 5e [2] ef 72 [2] c1 50 [2] d5 4b [2] da 51 [2] c4 4c [2] c6 4d [2] dd 4b [2] c1 4c [2] dd 63 }

  condition:
    any of them
}