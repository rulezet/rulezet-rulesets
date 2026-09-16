rule TTP_XOR_QUAD_CurrentVersionRun_07d8 {
  strings:
    $key_07d8 = { 54 b7 [2] 70 b9 [2] 5b 95 [2] 75 b7 [2] 61 ac [2] 6e b6 [2] 70 ab [2] 72 aa [2] 69 ac [2] 75 ab [2] 69 84 }

  condition:
    any of them
}