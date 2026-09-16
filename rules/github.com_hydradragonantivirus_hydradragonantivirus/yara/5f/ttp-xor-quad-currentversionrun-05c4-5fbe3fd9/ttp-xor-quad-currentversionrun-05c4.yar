rule TTP_XOR_QUAD_CurrentVersionRun_05c4 {
  strings:
    $key_05c4 = { 56 ab [2] 72 a5 [2] 59 89 [2] 77 ab [2] 63 b0 [2] 6c aa [2] 72 b7 [2] 70 b6 [2] 6b b0 [2] 77 b7 [2] 6b 98 }

  condition:
    any of them
}