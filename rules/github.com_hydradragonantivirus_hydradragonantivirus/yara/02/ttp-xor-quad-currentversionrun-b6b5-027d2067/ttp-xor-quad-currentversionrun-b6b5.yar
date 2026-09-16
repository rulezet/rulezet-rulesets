rule TTP_XOR_QUAD_CurrentVersionRun_b6b5 {
  strings:
    $key_b6b5 = { e5 da [2] c1 d4 [2] ea f8 [2] c4 da [2] d0 c1 [2] df db [2] c1 c6 [2] c3 c7 [2] d8 c1 [2] c4 c6 [2] d8 e9 }

  condition:
    any of them
}