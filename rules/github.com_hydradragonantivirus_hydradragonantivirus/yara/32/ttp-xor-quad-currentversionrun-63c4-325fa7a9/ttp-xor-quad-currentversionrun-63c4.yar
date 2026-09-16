rule TTP_XOR_QUAD_CurrentVersionRun_63c4 {
  strings:
    $key_63c4 = { 30 ab [2] 14 a5 [2] 3f 89 [2] 11 ab [2] 05 b0 [2] 0a aa [2] 14 b7 [2] 16 b6 [2] 0d b0 [2] 11 b7 [2] 0d 98 }

  condition:
    any of them
}