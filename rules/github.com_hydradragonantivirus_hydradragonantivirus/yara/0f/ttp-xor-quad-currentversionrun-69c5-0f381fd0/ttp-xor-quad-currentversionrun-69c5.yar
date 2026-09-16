rule TTP_XOR_QUAD_CurrentVersionRun_69c5 {
  strings:
    $key_69c5 = { 3a aa [2] 1e a4 [2] 35 88 [2] 1b aa [2] 0f b1 [2] 00 ab [2] 1e b6 [2] 1c b7 [2] 07 b1 [2] 1b b6 [2] 07 99 }

  condition:
    any of them
}