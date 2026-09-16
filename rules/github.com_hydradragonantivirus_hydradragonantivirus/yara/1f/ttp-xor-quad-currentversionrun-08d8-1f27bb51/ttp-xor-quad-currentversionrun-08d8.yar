rule TTP_XOR_QUAD_CurrentVersionRun_08d8 {
  strings:
    $key_08d8 = { 5b b7 [2] 7f b9 [2] 54 95 [2] 7a b7 [2] 6e ac [2] 61 b6 [2] 7f ab [2] 7d aa [2] 66 ac [2] 7a ab [2] 66 84 }

  condition:
    any of them
}