rule TTP_XOR_QUAD_CurrentVersionRun_afaa {
  strings:
    $key_afaa = { fc c5 [2] d8 cb [2] f3 e7 [2] dd c5 [2] c9 de [2] c6 c4 [2] d8 d9 [2] da d8 [2] c1 de [2] dd d9 [2] c1 f6 }

  condition:
    any of them
}