rule TTP_XOR_QUAD_CurrentVersionRun_35d8 {
  strings:
    $key_35d8 = { 66 b7 [2] 42 b9 [2] 69 95 [2] 47 b7 [2] 53 ac [2] 5c b6 [2] 42 ab [2] 40 aa [2] 5b ac [2] 47 ab [2] 5b 84 }

  condition:
    any of them
}