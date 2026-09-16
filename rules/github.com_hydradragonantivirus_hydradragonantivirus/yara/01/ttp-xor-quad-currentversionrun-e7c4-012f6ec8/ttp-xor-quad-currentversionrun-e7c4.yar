rule TTP_XOR_QUAD_CurrentVersionRun_e7c4 {
  strings:
    $key_e7c4 = { b4 ab [2] 90 a5 [2] bb 89 [2] 95 ab [2] 81 b0 [2] 8e aa [2] 90 b7 [2] 92 b6 [2] 89 b0 [2] 95 b7 [2] 89 98 }

  condition:
    any of them
}