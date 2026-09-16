rule TTP_XOR_QUAD_CurrentVersionRun_aac4 {
  strings:
    $key_aac4 = { f9 ab [2] dd a5 [2] f6 89 [2] d8 ab [2] cc b0 [2] c3 aa [2] dd b7 [2] df b6 [2] c4 b0 [2] d8 b7 [2] c4 98 }

  condition:
    any of them
}