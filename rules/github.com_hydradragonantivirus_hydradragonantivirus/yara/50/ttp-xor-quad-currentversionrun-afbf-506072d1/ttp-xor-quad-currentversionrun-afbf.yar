rule TTP_XOR_QUAD_CurrentVersionRun_afbf {
  strings:
    $key_afbf = { fc d0 [2] d8 de [2] f3 f2 [2] dd d0 [2] c9 cb [2] c6 d1 [2] d8 cc [2] da cd [2] c1 cb [2] dd cc [2] c1 e3 }

  condition:
    any of them
}