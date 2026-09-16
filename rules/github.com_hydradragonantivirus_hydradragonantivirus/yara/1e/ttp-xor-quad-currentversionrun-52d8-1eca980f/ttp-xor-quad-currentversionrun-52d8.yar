rule TTP_XOR_QUAD_CurrentVersionRun_52d8 {
  strings:
    $key_52d8 = { 01 b7 [2] 25 b9 [2] 0e 95 [2] 20 b7 [2] 34 ac [2] 3b b6 [2] 25 ab [2] 27 aa [2] 3c ac [2] 20 ab [2] 3c 84 }

  condition:
    any of them
}