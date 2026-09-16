rule TTP_XOR_QUAD_CurrentVersionRun_b30b {
  strings:
    $key_b30b = { e0 64 [2] c4 6a [2] ef 46 [2] c1 64 [2] d5 7f [2] da 65 [2] c4 78 [2] c6 79 [2] dd 7f [2] c1 78 [2] dd 57 }

  condition:
    any of them
}