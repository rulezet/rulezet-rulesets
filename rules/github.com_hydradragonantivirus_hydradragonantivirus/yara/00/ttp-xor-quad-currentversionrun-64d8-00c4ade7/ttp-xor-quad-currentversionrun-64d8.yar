rule TTP_XOR_QUAD_CurrentVersionRun_64d8 {
  strings:
    $key_64d8 = { 37 b7 [2] 13 b9 [2] 38 95 [2] 16 b7 [2] 02 ac [2] 0d b6 [2] 13 ab [2] 11 aa [2] 0a ac [2] 16 ab [2] 0a 84 }

  condition:
    any of them
}