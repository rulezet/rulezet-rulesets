rule TTP_XOR_QUAD_CurrentVersionRun_b33e {
  strings:
    $key_b33e = { e0 51 [2] c4 5f [2] ef 73 [2] c1 51 [2] d5 4a [2] da 50 [2] c4 4d [2] c6 4c [2] dd 4a [2] c1 4d [2] dd 62 }

  condition:
    any of them
}