rule TTP_XOR_QUAD_CurrentVersionRun_afad {
  strings:
    $key_afad = { fc c2 [2] d8 cc [2] f3 e0 [2] dd c2 [2] c9 d9 [2] c6 c3 [2] d8 de [2] da df [2] c1 d9 [2] dd de [2] c1 f1 }

  condition:
    any of them
}