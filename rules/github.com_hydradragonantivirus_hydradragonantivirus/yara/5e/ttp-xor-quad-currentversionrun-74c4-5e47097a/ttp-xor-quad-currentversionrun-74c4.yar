rule TTP_XOR_QUAD_CurrentVersionRun_74c4 {
  strings:
    $key_74c4 = { 27 ab [2] 03 a5 [2] 28 89 [2] 06 ab [2] 12 b0 [2] 1d aa [2] 03 b7 [2] 01 b6 [2] 1a b0 [2] 06 b7 [2] 1a 98 }

  condition:
    any of them
}