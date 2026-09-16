rule TTP_XOR_QUAD_CurrentVersionRun_aac2 {
  strings:
    $key_aac2 = { f9 ad [2] dd a3 [2] f6 8f [2] d8 ad [2] cc b6 [2] c3 ac [2] dd b1 [2] df b0 [2] c4 b6 [2] d8 b1 [2] c4 9e }

  condition:
    any of them
}