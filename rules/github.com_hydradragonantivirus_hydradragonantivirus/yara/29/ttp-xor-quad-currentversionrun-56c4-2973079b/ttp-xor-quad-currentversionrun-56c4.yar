rule TTP_XOR_QUAD_CurrentVersionRun_56c4 {
  strings:
    $key_56c4 = { 05 ab [2] 21 a5 [2] 0a 89 [2] 24 ab [2] 30 b0 [2] 3f aa [2] 21 b7 [2] 23 b6 [2] 38 b0 [2] 24 b7 [2] 38 98 }

  condition:
    any of them
}