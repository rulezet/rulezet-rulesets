rule TTP_XOR_QUAD_CurrentVersionRun_33c4 {
  strings:
    $key_33c4 = { 60 ab [2] 44 a5 [2] 6f 89 [2] 41 ab [2] 55 b0 [2] 5a aa [2] 44 b7 [2] 46 b6 [2] 5d b0 [2] 41 b7 [2] 5d 98 }

  condition:
    any of them
}