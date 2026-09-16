rule TTP_XOR_QUAD_CurrentVersionRun_aaa5 {
  strings:
    $key_aaa5 = { f9 ca [2] dd c4 [2] f6 e8 [2] d8 ca [2] cc d1 [2] c3 cb [2] dd d6 [2] df d7 [2] c4 d1 [2] d8 d6 [2] c4 f9 }

  condition:
    any of them
}