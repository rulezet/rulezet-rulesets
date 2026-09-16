rule TTP_XOR_QUAD_CurrentVersionRun_52c5 {
  strings:
    $key_52c5 = { 01 aa [2] 25 a4 [2] 0e 88 [2] 20 aa [2] 34 b1 [2] 3b ab [2] 25 b6 [2] 27 b7 [2] 3c b1 [2] 20 b6 [2] 3c 99 }

  condition:
    any of them
}