rule TTP_XOR_QUAD_CurrentVersionRun_b301 {
  strings:
    $key_b301 = { e0 6e [2] c4 60 [2] ef 4c [2] c1 6e [2] d5 75 [2] da 6f [2] c4 72 [2] c6 73 [2] dd 75 [2] c1 72 [2] dd 5d }

  condition:
    any of them
}