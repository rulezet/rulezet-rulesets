rule TTP_XOR_QUAD_CurrentVersionRun_b33c {
  strings:
    $key_b33c = { e0 53 [2] c4 5d [2] ef 71 [2] c1 53 [2] d5 48 [2] da 52 [2] c4 4f [2] c6 4e [2] dd 48 [2] c1 4f [2] dd 60 }

  condition:
    any of them
}