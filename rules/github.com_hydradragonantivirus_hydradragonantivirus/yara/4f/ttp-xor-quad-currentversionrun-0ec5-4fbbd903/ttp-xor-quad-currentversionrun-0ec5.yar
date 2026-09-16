rule TTP_XOR_QUAD_CurrentVersionRun_0ec5 {
  strings:
    $key_0ec5 = { 5d aa [2] 79 a4 [2] 52 88 [2] 7c aa [2] 68 b1 [2] 67 ab [2] 79 b6 [2] 7b b7 [2] 60 b1 [2] 7c b6 [2] 60 99 }

  condition:
    any of them
}