rule TTP_XOR_QUAD_CurrentVersionRun_afa4 {
  strings:
    $key_afa4 = { fc cb [2] d8 c5 [2] f3 e9 [2] dd cb [2] c9 d0 [2] c6 ca [2] d8 d7 [2] da d6 [2] c1 d0 [2] dd d7 [2] c1 f8 }

  condition:
    any of them
}