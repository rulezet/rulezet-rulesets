rule TTP_XOR_QUAD_CurrentVersionRun_77d8 {
  strings:
    $key_77d8 = { 24 b7 [2] 00 b9 [2] 2b 95 [2] 05 b7 [2] 11 ac [2] 1e b6 [2] 00 ab [2] 02 aa [2] 19 ac [2] 05 ab [2] 19 84 }

  condition:
    any of them
}