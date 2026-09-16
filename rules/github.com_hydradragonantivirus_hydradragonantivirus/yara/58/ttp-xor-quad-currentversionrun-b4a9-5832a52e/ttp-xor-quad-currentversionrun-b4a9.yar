rule TTP_XOR_QUAD_CurrentVersionRun_b4a9 {
  strings:
    $key_b4a9 = { e7 c6 [2] c3 c8 [2] e8 e4 [2] c6 c6 [2] d2 dd [2] dd c7 [2] c3 da [2] c1 db [2] da dd [2] c6 da [2] da f5 }

  condition:
    any of them
}