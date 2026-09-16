rule TTP_XOR_QUAD_CurrentVersionRun_0cd8 {
  strings:
    $key_0cd8 = { 5f b7 [2] 7b b9 [2] 50 95 [2] 7e b7 [2] 6a ac [2] 65 b6 [2] 7b ab [2] 79 aa [2] 62 ac [2] 7e ab [2] 62 84 }

  condition:
    any of them
}