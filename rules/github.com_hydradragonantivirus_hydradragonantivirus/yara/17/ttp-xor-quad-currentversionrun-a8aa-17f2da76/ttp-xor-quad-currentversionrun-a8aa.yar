rule TTP_XOR_QUAD_CurrentVersionRun_a8aa {
  strings:
    $key_a8aa = { fb c5 [2] df cb [2] f4 e7 [2] da c5 [2] ce de [2] c1 c4 [2] df d9 [2] dd d8 [2] c6 de [2] da d9 [2] c6 f6 }

  condition:
    any of them
}