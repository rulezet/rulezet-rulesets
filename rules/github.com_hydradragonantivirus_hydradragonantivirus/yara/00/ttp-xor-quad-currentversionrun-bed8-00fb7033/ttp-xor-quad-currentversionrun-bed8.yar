rule TTP_XOR_QUAD_CurrentVersionRun_bed8 {
  strings:
    $key_bed8 = { ed b7 [2] c9 b9 [2] e2 95 [2] cc b7 [2] d8 ac [2] d7 b6 [2] c9 ab [2] cb aa [2] d0 ac [2] cc ab [2] d0 84 }

  condition:
    any of them
}