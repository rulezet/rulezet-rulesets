rule TTP_XOR_QUAD_CurrentVersionRun_07c4 {
  strings:
    $key_07c4 = { 54 ab [2] 70 a5 [2] 5b 89 [2] 75 ab [2] 61 b0 [2] 6e aa [2] 70 b7 [2] 72 b6 [2] 69 b0 [2] 75 b7 [2] 69 98 }

  condition:
    any of them
}