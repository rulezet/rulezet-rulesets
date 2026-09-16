rule TTP_XOR_QUAD_CurrentVersionRun_aaa4 {
  strings:
    $key_aaa4 = { f9 cb [2] dd c5 [2] f6 e9 [2] d8 cb [2] cc d0 [2] c3 ca [2] dd d7 [2] df d6 [2] c4 d0 [2] d8 d7 [2] c4 f8 }

  condition:
    any of them
}