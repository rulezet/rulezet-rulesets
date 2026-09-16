rule TTP_XOR_QUAD_CurrentVersionRun_79c4 {
  strings:
    $key_79c4 = { 2a ab [2] 0e a5 [2] 25 89 [2] 0b ab [2] 1f b0 [2] 10 aa [2] 0e b7 [2] 0c b6 [2] 17 b0 [2] 0b b7 [2] 17 98 }

  condition:
    any of them
}