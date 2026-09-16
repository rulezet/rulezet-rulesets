rule TTP_XOR_QUAD_CurrentVersionRun_afb8 {
  strings:
    $key_afb8 = { fc d7 [2] d8 d9 [2] f3 f5 [2] dd d7 [2] c9 cc [2] c6 d6 [2] d8 cb [2] da ca [2] c1 cc [2] dd cb [2] c1 e4 }

  condition:
    any of them
}