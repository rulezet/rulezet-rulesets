rule TTP_XOR_QUAD_CurrentVersionRun_f2c7 {
  strings:
    $key_f2c7 = { a1 a8 [2] 85 a6 [2] ae 8a [2] 80 a8 [2] 94 b3 [2] 9b a9 [2] 85 b4 [2] 87 b5 [2] 9c b3 [2] 80 b4 [2] 9c 9b }

  condition:
    any of them
}