rule TTP_XOR_QUAD_CurrentVersionRun_2fd8 {
  strings:
    $key_2fd8 = { 7c b7 [2] 58 b9 [2] 73 95 [2] 5d b7 [2] 49 ac [2] 46 b6 [2] 58 ab [2] 5a aa [2] 41 ac [2] 5d ab [2] 41 84 }

  condition:
    any of them
}