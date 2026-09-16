rule TTP_XOR_QUAD_CurrentVersionRun_b3f3 {
  strings:
    $key_b3f3 = { e0 9c [2] c4 92 [2] ef be [2] c1 9c [2] d5 87 [2] da 9d [2] c4 80 [2] c6 81 [2] dd 87 [2] c1 80 [2] dd af }

  condition:
    any of them
}