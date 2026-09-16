rule TTP_XOR_QUAD_CurrentVersionRun_6bd8 {
  strings:
    $key_6bd8 = { 38 b7 [2] 1c b9 [2] 37 95 [2] 19 b7 [2] 0d ac [2] 02 b6 [2] 1c ab [2] 1e aa [2] 05 ac [2] 19 ab [2] 05 84 }

  condition:
    any of them
}