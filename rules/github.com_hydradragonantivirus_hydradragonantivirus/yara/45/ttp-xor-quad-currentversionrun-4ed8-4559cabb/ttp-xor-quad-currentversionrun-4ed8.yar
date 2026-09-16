rule TTP_XOR_QUAD_CurrentVersionRun_4ed8 {
  strings:
    $key_4ed8 = { 1d b7 [2] 39 b9 [2] 12 95 [2] 3c b7 [2] 28 ac [2] 27 b6 [2] 39 ab [2] 3b aa [2] 20 ac [2] 3c ab [2] 20 84 }

  condition:
    any of them
}