rule TTP_XOR_QUAD_CurrentVersionRun_b6d5 {
  strings:
    $key_b6d5 = { e5 ba [2] c1 b4 [2] ea 98 [2] c4 ba [2] d0 a1 [2] df bb [2] c1 a6 [2] c3 a7 [2] d8 a1 [2] c4 a6 [2] d8 89 }

  condition:
    any of them
}