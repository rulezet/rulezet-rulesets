rule TTP_XOR_QUAD_CurrentVersionRun_afa9 {
  strings:
    $key_afa9 = { fc c6 [2] d8 c8 [2] f3 e4 [2] dd c6 [2] c9 dd [2] c6 c7 [2] d8 da [2] da db [2] c1 dd [2] dd da [2] c1 f5 }

  condition:
    any of them
}