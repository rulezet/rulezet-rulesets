rule TTP_XOR_QUAD_CurrentVersionRun_b317 {
  strings:
    $key_b317 = { e0 78 [2] c4 76 [2] ef 5a [2] c1 78 [2] d5 63 [2] da 79 [2] c4 64 [2] c6 65 [2] dd 63 [2] c1 64 [2] dd 4b }

  condition:
    any of them
}