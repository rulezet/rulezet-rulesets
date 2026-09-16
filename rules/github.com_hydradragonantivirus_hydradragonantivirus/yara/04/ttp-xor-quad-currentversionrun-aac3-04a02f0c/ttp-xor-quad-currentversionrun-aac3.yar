rule TTP_XOR_QUAD_CurrentVersionRun_aac3 {
  strings:
    $key_aac3 = { f9 ac [2] dd a2 [2] f6 8e [2] d8 ac [2] cc b7 [2] c3 ad [2] dd b0 [2] df b1 [2] c4 b7 [2] d8 b0 [2] c4 9f }

  condition:
    any of them
}