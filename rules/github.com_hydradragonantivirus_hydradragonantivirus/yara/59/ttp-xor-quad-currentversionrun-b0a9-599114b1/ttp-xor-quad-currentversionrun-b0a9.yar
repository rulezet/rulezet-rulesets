rule TTP_XOR_QUAD_CurrentVersionRun_b0a9 {
  strings:
    $key_b0a9 = { e3 c6 [2] c7 c8 [2] ec e4 [2] c2 c6 [2] d6 dd [2] d9 c7 [2] c7 da [2] c5 db [2] de dd [2] c2 da [2] de f5 }

  condition:
    any of them
}