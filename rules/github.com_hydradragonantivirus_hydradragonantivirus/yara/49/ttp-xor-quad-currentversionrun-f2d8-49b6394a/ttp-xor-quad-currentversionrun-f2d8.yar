rule TTP_XOR_QUAD_CurrentVersionRun_f2d8 {
  strings:
    $key_f2d8 = { a1 b7 [2] 85 b9 [2] ae 95 [2] 80 b7 [2] 94 ac [2] 9b b6 [2] 85 ab [2] 87 aa [2] 9c ac [2] 80 ab [2] 9c 84 }

  condition:
    any of them
}