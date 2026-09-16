rule TTP_XOR_QUAD_CurrentVersionRun_9ad8 {
  strings:
    $key_9ad8 = { c9 b7 [2] ed b9 [2] c6 95 [2] e8 b7 [2] fc ac [2] f3 b6 [2] ed ab [2] ef aa [2] f4 ac [2] e8 ab [2] f4 84 }

  condition:
    any of them
}