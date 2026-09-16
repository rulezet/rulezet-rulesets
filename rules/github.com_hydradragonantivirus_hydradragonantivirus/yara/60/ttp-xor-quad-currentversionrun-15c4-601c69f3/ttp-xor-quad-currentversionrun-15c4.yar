rule TTP_XOR_QUAD_CurrentVersionRun_15c4 {
  strings:
    $key_15c4 = { 46 ab [2] 62 a5 [2] 49 89 [2] 67 ab [2] 73 b0 [2] 7c aa [2] 62 b7 [2] 60 b6 [2] 7b b0 [2] 67 b7 [2] 7b 98 }

  condition:
    any of them
}