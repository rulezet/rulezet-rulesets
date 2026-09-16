rule TTP_XOR_QUAD_CurrentVersionRun_b32c {
  strings:
    $key_b32c = { e0 43 [2] c4 4d [2] ef 61 [2] c1 43 [2] d5 58 [2] da 42 [2] c4 5f [2] c6 5e [2] dd 58 [2] c1 5f [2] dd 70 }

  condition:
    any of them
}