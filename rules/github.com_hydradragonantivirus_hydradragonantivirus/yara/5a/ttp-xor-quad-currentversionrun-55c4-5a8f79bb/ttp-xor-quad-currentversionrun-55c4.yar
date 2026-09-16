rule TTP_XOR_QUAD_CurrentVersionRun_55c4 {
  strings:
    $key_55c4 = { 06 ab [2] 22 a5 [2] 09 89 [2] 27 ab [2] 33 b0 [2] 3c aa [2] 22 b7 [2] 20 b6 [2] 3b b0 [2] 27 b7 [2] 3b 98 }

  condition:
    any of them
}