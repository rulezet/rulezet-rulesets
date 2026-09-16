rule TTP_XOR_QUAD_CurrentVersionRun_52c4 {
  strings:
    $key_52c4 = { 01 ab [2] 25 a5 [2] 0e 89 [2] 20 ab [2] 34 b0 [2] 3b aa [2] 25 b7 [2] 27 b6 [2] 3c b0 [2] 20 b7 [2] 3c 98 }

  condition:
    any of them
}