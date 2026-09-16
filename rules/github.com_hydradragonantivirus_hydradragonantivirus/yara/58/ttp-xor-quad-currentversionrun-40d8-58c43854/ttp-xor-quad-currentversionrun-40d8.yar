rule TTP_XOR_QUAD_CurrentVersionRun_40d8 {
  strings:
    $key_40d8 = { 13 b7 [2] 37 b9 [2] 1c 95 [2] 32 b7 [2] 26 ac [2] 29 b6 [2] 37 ab [2] 35 aa [2] 2e ac [2] 32 ab [2] 2e 84 }

  condition:
    any of them
}