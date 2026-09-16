rule TTP_XOR_QUAD_CurrentVersionRun_24d8 {
  strings:
    $key_24d8 = { 77 b7 [2] 53 b9 [2] 78 95 [2] 56 b7 [2] 42 ac [2] 4d b6 [2] 53 ab [2] 51 aa [2] 4a ac [2] 56 ab [2] 4a 84 }

  condition:
    any of them
}