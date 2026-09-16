rule TTP_XOR_QUAD_CurrentVersionRun_65d8 {
  strings:
    $key_65d8 = { 36 b7 [2] 12 b9 [2] 39 95 [2] 17 b7 [2] 03 ac [2] 0c b6 [2] 12 ab [2] 10 aa [2] 0b ac [2] 17 ab [2] 0b 84 }

  condition:
    any of them
}