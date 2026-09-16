rule TTP_XOR_QUAD_CurrentVersionRun_31d8 {
  strings:
    $key_31d8 = { 62 b7 [2] 46 b9 [2] 6d 95 [2] 43 b7 [2] 57 ac [2] 58 b6 [2] 46 ab [2] 44 aa [2] 5f ac [2] 43 ab [2] 5f 84 }

  condition:
    any of them
}