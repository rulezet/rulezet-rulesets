rule TTP_XOR_QUAD_CurrentVersionRun_f2c5 {
  strings:
    $key_f2c5 = { a1 aa [2] 85 a4 [2] ae 88 [2] 80 aa [2] 94 b1 [2] 9b ab [2] 85 b6 [2] 87 b7 [2] 9c b1 [2] 80 b6 [2] 9c 99 }

  condition:
    any of them
}