rule TTP_XOR_QUAD_CurrentVersionRun_72d8 {
  strings:
    $key_72d8 = { 21 b7 [2] 05 b9 [2] 2e 95 [2] 00 b7 [2] 14 ac [2] 1b b6 [2] 05 ab [2] 07 aa [2] 1c ac [2] 00 ab [2] 1c 84 }

  condition:
    any of them
}