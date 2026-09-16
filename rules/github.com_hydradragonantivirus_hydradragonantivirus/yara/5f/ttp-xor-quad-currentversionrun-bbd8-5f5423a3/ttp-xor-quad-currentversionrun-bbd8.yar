rule TTP_XOR_QUAD_CurrentVersionRun_bbd8 {
  strings:
    $key_bbd8 = { e8 b7 [2] cc b9 [2] e7 95 [2] c9 b7 [2] dd ac [2] d2 b6 [2] cc ab [2] ce aa [2] d5 ac [2] c9 ab [2] d5 84 }

  condition:
    any of them
}