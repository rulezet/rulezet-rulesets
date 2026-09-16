rule TTP_XOR_QUAD_CurrentVersionRun_afa5 {
  strings:
    $key_afa5 = { fc ca [2] d8 c4 [2] f3 e8 [2] dd ca [2] c9 d1 [2] c6 cb [2] d8 d6 [2] da d7 [2] c1 d1 [2] dd d6 [2] c1 f9 }

  condition:
    any of them
}