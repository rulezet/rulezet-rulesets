rule TTP_XOR_QUAD_CurrentVersionRun_67c4 {
  strings:
    $key_67c4 = { 34 ab [2] 10 a5 [2] 3b 89 [2] 15 ab [2] 01 b0 [2] 0e aa [2] 10 b7 [2] 12 b6 [2] 09 b0 [2] 15 b7 [2] 09 98 }

  condition:
    any of them
}