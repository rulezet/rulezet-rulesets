rule TTP_XOR_QUAD_CurrentVersionRun_5ed8 {
  strings:
    $key_5ed8 = { 0d b7 [2] 29 b9 [2] 02 95 [2] 2c b7 [2] 38 ac [2] 37 b6 [2] 29 ab [2] 2b aa [2] 30 ac [2] 2c ab [2] 30 84 }

  condition:
    any of them
}