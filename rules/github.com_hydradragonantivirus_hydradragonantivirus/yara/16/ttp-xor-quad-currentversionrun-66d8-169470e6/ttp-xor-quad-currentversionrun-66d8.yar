rule TTP_XOR_QUAD_CurrentVersionRun_66d8 {
  strings:
    $key_66d8 = { 35 b7 [2] 11 b9 [2] 3a 95 [2] 14 b7 [2] 00 ac [2] 0f b6 [2] 11 ab [2] 13 aa [2] 08 ac [2] 14 ab [2] 08 84 }

  condition:
    any of them
}