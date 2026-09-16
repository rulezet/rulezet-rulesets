rule TTP_XOR_QUAD_CurrentVersionRun_aad8 {
  strings:
    $key_aad8 = { f9 b7 [2] dd b9 [2] f6 95 [2] d8 b7 [2] cc ac [2] c3 b6 [2] dd ab [2] df aa [2] c4 ac [2] d8 ab [2] c4 84 }

  condition:
    any of them
}