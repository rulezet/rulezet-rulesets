rule TTP_XOR_QUAD_CurrentVersionRun_c8d8 {
  strings:
    $key_c8d8 = { 9b b7 [2] bf b9 [2] 94 95 [2] ba b7 [2] ae ac [2] a1 b6 [2] bf ab [2] bd aa [2] a6 ac [2] ba ab [2] a6 84 }

  condition:
    any of them
}