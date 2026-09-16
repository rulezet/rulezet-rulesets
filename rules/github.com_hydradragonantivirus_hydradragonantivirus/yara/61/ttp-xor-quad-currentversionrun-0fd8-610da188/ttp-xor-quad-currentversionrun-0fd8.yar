rule TTP_XOR_QUAD_CurrentVersionRun_0fd8 {
  strings:
    $key_0fd8 = { 5c b7 [2] 78 b9 [2] 53 95 [2] 7d b7 [2] 69 ac [2] 66 b6 [2] 78 ab [2] 7a aa [2] 61 ac [2] 7d ab [2] 61 84 }

  condition:
    any of them
}