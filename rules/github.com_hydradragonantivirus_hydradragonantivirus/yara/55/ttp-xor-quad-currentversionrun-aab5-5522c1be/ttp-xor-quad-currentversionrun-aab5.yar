rule TTP_XOR_QUAD_CurrentVersionRun_aab5 {
  strings:
    $key_aab5 = { f9 da [2] dd d4 [2] f6 f8 [2] d8 da [2] cc c1 [2] c3 db [2] dd c6 [2] df c7 [2] c4 c1 [2] d8 c6 [2] c4 e9 }

  condition:
    any of them
}