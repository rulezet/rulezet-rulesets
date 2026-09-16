rule TTP_XOR_QUAD_CurrentVersionRun_59d8 {
  strings:
    $key_59d8 = { 0a b7 [2] 2e b9 [2] 05 95 [2] 2b b7 [2] 3f ac [2] 30 b6 [2] 2e ab [2] 2c aa [2] 37 ac [2] 2b ab [2] 37 84 }

  condition:
    any of them
}