rule TTP_XOR_QUAD_CurrentVersionRun_bb86 {
  strings:
    $key_bb86 = { e8 e9 [2] cc e7 [2] e7 cb [2] c9 e9 [2] dd f2 [2] d2 e8 [2] cc f5 [2] ce f4 [2] d5 f2 [2] c9 f5 [2] d5 da }

  condition:
    any of them
}