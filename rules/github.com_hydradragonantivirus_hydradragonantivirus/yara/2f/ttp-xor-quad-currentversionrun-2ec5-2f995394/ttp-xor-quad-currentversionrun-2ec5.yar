rule TTP_XOR_QUAD_CurrentVersionRun_2ec5 {
  strings:
    $key_2ec5 = { 7d aa [2] 59 a4 [2] 72 88 [2] 5c aa [2] 48 b1 [2] 47 ab [2] 59 b6 [2] 5b b7 [2] 40 b1 [2] 5c b6 [2] 40 99 }

  condition:
    any of them
}