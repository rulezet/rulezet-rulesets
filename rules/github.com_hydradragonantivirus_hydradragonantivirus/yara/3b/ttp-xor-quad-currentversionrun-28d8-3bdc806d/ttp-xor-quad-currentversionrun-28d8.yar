rule TTP_XOR_QUAD_CurrentVersionRun_28d8 {
  strings:
    $key_28d8 = { 7b b7 [2] 5f b9 [2] 74 95 [2] 5a b7 [2] 4e ac [2] 41 b6 [2] 5f ab [2] 5d aa [2] 46 ac [2] 5a ab [2] 46 84 }

  condition:
    any of them
}