rule TTP_XOR_QUAD_CurrentVersionRun_5dd8 {
  strings:
    $key_5dd8 = { 0e b7 [2] 2a b9 [2] 01 95 [2] 2f b7 [2] 3b ac [2] 34 b6 [2] 2a ab [2] 28 aa [2] 33 ac [2] 2f ab [2] 33 84 }

  condition:
    any of them
}