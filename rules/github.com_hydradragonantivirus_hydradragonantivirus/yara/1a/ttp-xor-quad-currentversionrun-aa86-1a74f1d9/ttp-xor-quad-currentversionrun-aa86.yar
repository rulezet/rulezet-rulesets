rule TTP_XOR_QUAD_CurrentVersionRun_aa86 {
  strings:
    $key_aa86 = { f9 e9 [2] dd e7 [2] f6 cb [2] d8 e9 [2] cc f2 [2] c3 e8 [2] dd f5 [2] df f4 [2] c4 f2 [2] d8 f5 [2] c4 da }

  condition:
    any of them
}