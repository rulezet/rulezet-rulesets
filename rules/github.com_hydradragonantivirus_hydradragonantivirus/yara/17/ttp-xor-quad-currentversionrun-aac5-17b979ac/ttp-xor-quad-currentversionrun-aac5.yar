rule TTP_XOR_QUAD_CurrentVersionRun_aac5 {
  strings:
    $key_aac5 = { f9 aa [2] dd a4 [2] f6 88 [2] d8 aa [2] cc b1 [2] c3 ab [2] dd b6 [2] df b7 [2] c4 b1 [2] d8 b6 [2] c4 99 }

  condition:
    any of them
}