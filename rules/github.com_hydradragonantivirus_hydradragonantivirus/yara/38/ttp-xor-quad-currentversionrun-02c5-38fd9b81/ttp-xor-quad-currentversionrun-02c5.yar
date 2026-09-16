rule TTP_XOR_QUAD_CurrentVersionRun_02c5 {
  strings:
    $key_02c5 = { 51 aa [2] 75 a4 [2] 5e 88 [2] 70 aa [2] 64 b1 [2] 6b ab [2] 75 b6 [2] 77 b7 [2] 6c b1 [2] 70 b6 [2] 6c 99 }

  condition:
    any of them
}