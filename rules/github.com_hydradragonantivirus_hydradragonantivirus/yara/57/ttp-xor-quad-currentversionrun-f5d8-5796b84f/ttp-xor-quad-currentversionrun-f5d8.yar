rule TTP_XOR_QUAD_CurrentVersionRun_f5d8 {
  strings:
    $key_f5d8 = { a6 b7 [2] 82 b9 [2] a9 95 [2] 87 b7 [2] 93 ac [2] 9c b6 [2] 82 ab [2] 80 aa [2] 9b ac [2] 87 ab [2] 9b 84 }

  condition:
    any of them
}