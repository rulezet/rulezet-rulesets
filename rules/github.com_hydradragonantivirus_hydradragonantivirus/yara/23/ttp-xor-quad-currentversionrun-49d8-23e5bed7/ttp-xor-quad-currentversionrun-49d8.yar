rule TTP_XOR_QUAD_CurrentVersionRun_49d8 {
  strings:
    $key_49d8 = { 1a b7 [2] 3e b9 [2] 15 95 [2] 3b b7 [2] 2f ac [2] 20 b6 [2] 3e ab [2] 3c aa [2] 27 ac [2] 3b ab [2] 27 84 }

  condition:
    any of them
}