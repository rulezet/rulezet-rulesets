rule TTP_XOR_QUAD_CurrentVersionRun_42d8 {
  strings:
    $key_42d8 = { 11 b7 [2] 35 b9 [2] 1e 95 [2] 30 b7 [2] 24 ac [2] 2b b6 [2] 35 ab [2] 37 aa [2] 2c ac [2] 30 ab [2] 2c 84 }

  condition:
    any of them
}