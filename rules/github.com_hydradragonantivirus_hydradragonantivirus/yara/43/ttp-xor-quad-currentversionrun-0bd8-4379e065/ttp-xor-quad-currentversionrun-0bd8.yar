rule TTP_XOR_QUAD_CurrentVersionRun_0bd8 {
  strings:
    $key_0bd8 = { 58 b7 [2] 7c b9 [2] 57 95 [2] 79 b7 [2] 6d ac [2] 62 b6 [2] 7c ab [2] 7e aa [2] 65 ac [2] 79 ab [2] 65 84 }

  condition:
    any of them
}