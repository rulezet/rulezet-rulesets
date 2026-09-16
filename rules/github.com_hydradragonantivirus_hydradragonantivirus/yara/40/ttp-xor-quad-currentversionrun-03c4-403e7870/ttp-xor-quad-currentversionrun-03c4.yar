rule TTP_XOR_QUAD_CurrentVersionRun_03c4 {
  strings:
    $key_03c4 = { 50 ab [2] 74 a5 [2] 5f 89 [2] 71 ab [2] 65 b0 [2] 6a aa [2] 74 b7 [2] 76 b6 [2] 6d b0 [2] 71 b7 [2] 6d 98 }

  condition:
    any of them
}