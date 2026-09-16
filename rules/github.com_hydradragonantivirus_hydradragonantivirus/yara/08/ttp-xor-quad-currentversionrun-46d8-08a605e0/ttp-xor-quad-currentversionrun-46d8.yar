rule TTP_XOR_QUAD_CurrentVersionRun_46d8 {
  strings:
    $key_46d8 = { 15 b7 [2] 31 b9 [2] 1a 95 [2] 34 b7 [2] 20 ac [2] 2f b6 [2] 31 ab [2] 33 aa [2] 28 ac [2] 34 ab [2] 28 84 }

  condition:
    any of them
}