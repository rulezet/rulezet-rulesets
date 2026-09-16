rule TTP_XOR_QUAD_CurrentVersionRun_fed8 {
  strings:
    $key_fed8 = { ad b7 [2] 89 b9 [2] a2 95 [2] 8c b7 [2] 98 ac [2] 97 b6 [2] 89 ab [2] 8b aa [2] 90 ac [2] 8c ab [2] 90 84 }

  condition:
    any of them
}