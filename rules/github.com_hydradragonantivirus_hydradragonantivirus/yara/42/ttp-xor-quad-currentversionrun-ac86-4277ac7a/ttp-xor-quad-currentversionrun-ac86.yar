rule TTP_XOR_QUAD_CurrentVersionRun_ac86 {
  strings:
    $key_ac86 = { ff e9 [2] db e7 [2] f0 cb [2] de e9 [2] ca f2 [2] c5 e8 [2] db f5 [2] d9 f4 [2] c2 f2 [2] de f5 [2] c2 da }

  condition:
    any of them
}