rule TTP_XOR_QUAD_CurrentVersionRun_b33d {
  strings:
    $key_b33d = { e0 52 [2] c4 5c [2] ef 70 [2] c1 52 [2] d5 49 [2] da 53 [2] c4 4e [2] c6 4f [2] dd 49 [2] c1 4e [2] dd 61 }

  condition:
    any of them
}