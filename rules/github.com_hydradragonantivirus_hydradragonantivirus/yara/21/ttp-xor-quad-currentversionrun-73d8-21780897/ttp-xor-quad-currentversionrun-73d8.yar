rule TTP_XOR_QUAD_CurrentVersionRun_73d8 {
  strings:
    $key_73d8 = { 20 b7 [2] 04 b9 [2] 2f 95 [2] 01 b7 [2] 15 ac [2] 1a b6 [2] 04 ab [2] 06 aa [2] 1d ac [2] 01 ab [2] 1d 84 }

  condition:
    any of them
}