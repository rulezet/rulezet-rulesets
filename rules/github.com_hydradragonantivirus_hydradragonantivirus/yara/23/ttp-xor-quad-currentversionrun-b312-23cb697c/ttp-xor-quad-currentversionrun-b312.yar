rule TTP_XOR_QUAD_CurrentVersionRun_b312 {
  strings:
    $key_b312 = { e0 7d [2] c4 73 [2] ef 5f [2] c1 7d [2] d5 66 [2] da 7c [2] c4 61 [2] c6 60 [2] dd 66 [2] c1 61 [2] dd 4e }

  condition:
    any of them
}