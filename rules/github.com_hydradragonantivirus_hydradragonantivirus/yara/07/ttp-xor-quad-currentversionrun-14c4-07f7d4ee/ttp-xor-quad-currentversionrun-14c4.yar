rule TTP_XOR_QUAD_CurrentVersionRun_14c4 {
  strings:
    $key_14c4 = { 47 ab [2] 63 a5 [2] 48 89 [2] 66 ab [2] 72 b0 [2] 7d aa [2] 63 b7 [2] 61 b6 [2] 7a b0 [2] 66 b7 [2] 7a 98 }

  condition:
    any of them
}