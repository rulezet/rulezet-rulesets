rule TTP_XOR_QUAD_CurrentVersionRun_27d8 {
  strings:
    $key_27d8 = { 74 b7 [2] 50 b9 [2] 7b 95 [2] 55 b7 [2] 41 ac [2] 4e b6 [2] 50 ab [2] 52 aa [2] 49 ac [2] 55 ab [2] 49 84 }

  condition:
    any of them
}