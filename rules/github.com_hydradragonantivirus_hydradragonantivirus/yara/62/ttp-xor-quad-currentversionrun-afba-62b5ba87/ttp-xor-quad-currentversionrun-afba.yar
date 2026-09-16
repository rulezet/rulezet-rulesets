rule TTP_XOR_QUAD_CurrentVersionRun_afba {
  strings:
    $key_afba = { fc d5 [2] d8 db [2] f3 f7 [2] dd d5 [2] c9 ce [2] c6 d4 [2] d8 c9 [2] da c8 [2] c1 ce [2] dd c9 [2] c1 e6 }

  condition:
    any of them
}