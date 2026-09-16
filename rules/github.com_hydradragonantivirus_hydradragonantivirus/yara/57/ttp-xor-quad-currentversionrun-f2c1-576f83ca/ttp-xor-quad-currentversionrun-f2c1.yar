rule TTP_XOR_QUAD_CurrentVersionRun_f2c1 {
  strings:
    $key_f2c1 = { a1 ae [2] 85 a0 [2] ae 8c [2] 80 ae [2] 94 b5 [2] 9b af [2] 85 b2 [2] 87 b3 [2] 9c b5 [2] 80 b2 [2] 9c 9d }

  condition:
    any of them
}