rule TTP_XOR_QUAD_CurrentVersionRun_b30d {
  strings:
    $key_b30d = { e0 62 [2] c4 6c [2] ef 40 [2] c1 62 [2] d5 79 [2] da 63 [2] c4 7e [2] c6 7f [2] dd 79 [2] c1 7e [2] dd 51 }

  condition:
    any of them
}