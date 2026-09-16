rule TTP_XOR_QUAD_CurrentVersionRun_23d8 {
  strings:
    $key_23d8 = { 70 b7 [2] 54 b9 [2] 7f 95 [2] 51 b7 [2] 45 ac [2] 4a b6 [2] 54 ab [2] 56 aa [2] 4d ac [2] 51 ab [2] 4d 84 }

  condition:
    any of them
}