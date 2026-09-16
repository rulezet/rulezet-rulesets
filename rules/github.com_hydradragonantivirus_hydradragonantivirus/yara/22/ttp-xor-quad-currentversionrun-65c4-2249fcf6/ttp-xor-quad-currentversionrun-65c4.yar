rule TTP_XOR_QUAD_CurrentVersionRun_65c4 {
  strings:
    $key_65c4 = { 36 ab [2] 12 a5 [2] 39 89 [2] 17 ab [2] 03 b0 [2] 0c aa [2] 12 b7 [2] 10 b6 [2] 0b b0 [2] 17 b7 [2] 0b 98 }

  condition:
    any of them
}