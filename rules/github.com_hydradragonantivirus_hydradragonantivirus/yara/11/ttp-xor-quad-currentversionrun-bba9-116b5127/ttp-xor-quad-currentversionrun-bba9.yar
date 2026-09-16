rule TTP_XOR_QUAD_CurrentVersionRun_bba9 {
  strings:
    $key_bba9 = { e8 c6 [2] cc c8 [2] e7 e4 [2] c9 c6 [2] dd dd [2] d2 c7 [2] cc da [2] ce db [2] d5 dd [2] c9 da [2] d5 f5 }

  condition:
    any of them
}