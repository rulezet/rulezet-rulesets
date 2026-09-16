rule TTP_XOR_QUAD_CurrentVersionRun_b30c {
  strings:
    $key_b30c = { e0 63 [2] c4 6d [2] ef 41 [2] c1 63 [2] d5 78 [2] da 62 [2] c4 7f [2] c6 7e [2] dd 78 [2] c1 7f [2] dd 50 }

  condition:
    any of them
}