rule TTP_XOR_QUAD_CurrentVersionRun_22c5 {
  strings:
    $key_22c5 = { 71 aa [2] 55 a4 [2] 7e 88 [2] 50 aa [2] 44 b1 [2] 4b ab [2] 55 b6 [2] 57 b7 [2] 4c b1 [2] 50 b6 [2] 4c 99 }

  condition:
    any of them
}