rule TTP_XOR_QUAD_CurrentVersionRun_69c4 {
  strings:
    $key_69c4 = { 3a ab [2] 1e a5 [2] 35 89 [2] 1b ab [2] 0f b0 [2] 00 aa [2] 1e b7 [2] 1c b6 [2] 07 b0 [2] 1b b7 [2] 07 98 }

  condition:
    any of them
}