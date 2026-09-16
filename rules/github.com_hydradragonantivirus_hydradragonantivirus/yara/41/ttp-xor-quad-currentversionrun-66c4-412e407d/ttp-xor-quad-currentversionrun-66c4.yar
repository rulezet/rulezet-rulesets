rule TTP_XOR_QUAD_CurrentVersionRun_66c4 {
  strings:
    $key_66c4 = { 35 ab [2] 11 a5 [2] 3a 89 [2] 14 ab [2] 00 b0 [2] 0f aa [2] 11 b7 [2] 13 b6 [2] 08 b0 [2] 14 b7 [2] 08 98 }

  condition:
    any of them
}