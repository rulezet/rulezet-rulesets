rule TTP_XOR_QUAD_CurrentVersionRun_1ec5 {
  strings:
    $key_1ec5 = { 4d aa [2] 69 a4 [2] 42 88 [2] 6c aa [2] 78 b1 [2] 77 ab [2] 69 b6 [2] 6b b7 [2] 70 b1 [2] 6c b6 [2] 70 99 }

  condition:
    any of them
}