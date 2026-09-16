rule TTP_XOR_QUAD_CurrentVersionRun_04d8 {
  strings:
    $key_04d8 = { 57 b7 [2] 73 b9 [2] 58 95 [2] 76 b7 [2] 62 ac [2] 6d b6 [2] 73 ab [2] 71 aa [2] 6a ac [2] 76 ab [2] 6a 84 }

  condition:
    any of them
}