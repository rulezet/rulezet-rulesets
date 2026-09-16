rule TTP_XOR_QUAD_CurrentVersionRun_06c4 {
  strings:
    $key_06c4 = { 55 ab [2] 71 a5 [2] 5a 89 [2] 74 ab [2] 60 b0 [2] 6f aa [2] 71 b7 [2] 73 b6 [2] 68 b0 [2] 74 b7 [2] 68 98 }

  condition:
    any of them
}