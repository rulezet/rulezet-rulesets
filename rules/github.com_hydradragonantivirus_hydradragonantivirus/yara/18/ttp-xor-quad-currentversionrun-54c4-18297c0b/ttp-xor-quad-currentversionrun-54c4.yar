rule TTP_XOR_QUAD_CurrentVersionRun_54c4 {
  strings:
    $key_54c4 = { 07 ab [2] 23 a5 [2] 08 89 [2] 26 ab [2] 32 b0 [2] 3d aa [2] 23 b7 [2] 21 b6 [2] 3a b0 [2] 26 b7 [2] 3a 98 }

  condition:
    any of them
}