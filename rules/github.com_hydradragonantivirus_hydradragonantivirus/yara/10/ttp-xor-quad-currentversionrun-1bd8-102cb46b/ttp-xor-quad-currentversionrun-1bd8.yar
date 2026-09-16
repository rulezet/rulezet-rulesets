rule TTP_XOR_QUAD_CurrentVersionRun_1bd8 {
  strings:
    $key_1bd8 = { 48 b7 [2] 6c b9 [2] 47 95 [2] 69 b7 [2] 7d ac [2] 72 b6 [2] 6c ab [2] 6e aa [2] 75 ac [2] 69 ab [2] 75 84 }

  condition:
    any of them
}