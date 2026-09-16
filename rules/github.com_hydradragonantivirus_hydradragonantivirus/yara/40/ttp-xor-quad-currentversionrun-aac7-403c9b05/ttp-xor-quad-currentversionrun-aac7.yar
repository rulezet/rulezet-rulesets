rule TTP_XOR_QUAD_CurrentVersionRun_aac7 {
  strings:
    $key_aac7 = { f9 a8 [2] dd a6 [2] f6 8a [2] d8 a8 [2] cc b3 [2] c3 a9 [2] dd b4 [2] df b5 [2] c4 b3 [2] d8 b4 [2] c4 9b }

  condition:
    any of them
}