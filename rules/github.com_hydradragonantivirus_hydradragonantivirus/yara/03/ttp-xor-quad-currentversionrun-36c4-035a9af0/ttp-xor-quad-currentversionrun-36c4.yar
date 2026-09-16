rule TTP_XOR_QUAD_CurrentVersionRun_36c4 {
  strings:
    $key_36c4 = { 65 ab [2] 41 a5 [2] 6a 89 [2] 44 ab [2] 50 b0 [2] 5f aa [2] 41 b7 [2] 43 b6 [2] 58 b0 [2] 44 b7 [2] 58 98 }

  condition:
    any of them
}