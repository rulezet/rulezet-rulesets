rule TTP_XOR_QUAD_CurrentVersionRun_18d8 {
  strings:
    $key_18d8 = { 4b b7 [2] 6f b9 [2] 44 95 [2] 6a b7 [2] 7e ac [2] 71 b6 [2] 6f ab [2] 6d aa [2] 76 ac [2] 6a ab [2] 76 84 }

  condition:
    any of them
}