rule TTP_XOR_QUAD_CurrentVersionRun_53d8 {
  strings:
    $key_53d8 = { 00 b7 [2] 24 b9 [2] 0f 95 [2] 21 b7 [2] 35 ac [2] 3a b6 [2] 24 ab [2] 26 aa [2] 3d ac [2] 21 ab [2] 3d 84 }

  condition:
    any of them
}