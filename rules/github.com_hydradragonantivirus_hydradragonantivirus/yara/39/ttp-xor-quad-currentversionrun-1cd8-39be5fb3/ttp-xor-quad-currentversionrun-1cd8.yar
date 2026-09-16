rule TTP_XOR_QUAD_CurrentVersionRun_1cd8 {
  strings:
    $key_1cd8 = { 4f b7 [2] 6b b9 [2] 40 95 [2] 6e b7 [2] 7a ac [2] 75 b6 [2] 6b ab [2] 69 aa [2] 72 ac [2] 6e ab [2] 72 84 }

  condition:
    any of them
}