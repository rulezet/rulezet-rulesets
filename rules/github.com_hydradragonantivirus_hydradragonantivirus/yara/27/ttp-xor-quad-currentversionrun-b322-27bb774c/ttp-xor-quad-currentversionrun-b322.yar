rule TTP_XOR_QUAD_CurrentVersionRun_b322 {
  strings:
    $key_b322 = { e0 4d [2] c4 43 [2] ef 6f [2] c1 4d [2] d5 56 [2] da 4c [2] c4 51 [2] c6 50 [2] dd 56 [2] c1 51 [2] dd 7e }

  condition:
    any of them
}