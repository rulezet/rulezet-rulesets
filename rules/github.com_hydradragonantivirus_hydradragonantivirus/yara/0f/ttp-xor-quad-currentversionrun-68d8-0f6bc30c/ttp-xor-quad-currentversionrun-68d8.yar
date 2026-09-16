rule TTP_XOR_QUAD_CurrentVersionRun_68d8 {
  strings:
    $key_68d8 = { 3b b7 [2] 1f b9 [2] 34 95 [2] 1a b7 [2] 0e ac [2] 01 b6 [2] 1f ab [2] 1d aa [2] 06 ac [2] 1a ab [2] 06 84 }

  condition:
    any of them
}