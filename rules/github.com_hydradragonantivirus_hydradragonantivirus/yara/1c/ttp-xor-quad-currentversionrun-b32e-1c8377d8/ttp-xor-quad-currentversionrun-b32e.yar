rule TTP_XOR_QUAD_CurrentVersionRun_b32e {
  strings:
    $key_b32e = { e0 41 [2] c4 4f [2] ef 63 [2] c1 41 [2] d5 5a [2] da 40 [2] c4 5d [2] c6 5c [2] dd 5a [2] c1 5d [2] dd 72 }

  condition:
    any of them
}