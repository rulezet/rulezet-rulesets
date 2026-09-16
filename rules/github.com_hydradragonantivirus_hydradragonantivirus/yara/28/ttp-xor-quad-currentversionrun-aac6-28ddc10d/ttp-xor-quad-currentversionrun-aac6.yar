rule TTP_XOR_QUAD_CurrentVersionRun_aac6 {
  strings:
    $key_aac6 = { f9 a9 [2] dd a7 [2] f6 8b [2] d8 a9 [2] cc b2 [2] c3 a8 [2] dd b5 [2] df b4 [2] c4 b2 [2] d8 b5 [2] c4 9a }

  condition:
    any of them
}