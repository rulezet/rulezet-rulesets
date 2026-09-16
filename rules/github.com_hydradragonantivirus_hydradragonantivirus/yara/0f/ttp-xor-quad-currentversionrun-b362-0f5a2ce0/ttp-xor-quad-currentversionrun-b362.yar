rule TTP_XOR_QUAD_CurrentVersionRun_b362 {
  strings:
    $key_b362 = { e0 0d [2] c4 03 [2] ef 2f [2] c1 0d [2] d5 16 [2] da 0c [2] c4 11 [2] c6 10 [2] dd 16 [2] c1 11 [2] dd 3e }

  condition:
    any of them
}