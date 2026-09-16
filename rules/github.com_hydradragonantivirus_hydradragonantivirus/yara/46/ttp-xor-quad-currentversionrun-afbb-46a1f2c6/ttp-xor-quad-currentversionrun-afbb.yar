rule TTP_XOR_QUAD_CurrentVersionRun_afbb {
  strings:
    $key_afbb = { fc d4 [2] d8 da [2] f3 f6 [2] dd d4 [2] c9 cf [2] c6 d5 [2] d8 c8 [2] da c9 [2] c1 cf [2] dd c8 [2] c1 e7 }

  condition:
    any of them
}