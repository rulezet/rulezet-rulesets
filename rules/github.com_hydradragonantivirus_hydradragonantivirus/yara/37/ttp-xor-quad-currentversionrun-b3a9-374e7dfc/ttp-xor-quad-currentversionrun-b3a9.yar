rule TTP_XOR_QUAD_CurrentVersionRun_b3a9 {
  strings:
    $key_b3a9 = { e0 c6 [2] c4 c8 [2] ef e4 [2] c1 c6 [2] d5 dd [2] da c7 [2] c4 da [2] c6 db [2] dd dd [2] c1 da [2] dd f5 }

  condition:
    any of them
}