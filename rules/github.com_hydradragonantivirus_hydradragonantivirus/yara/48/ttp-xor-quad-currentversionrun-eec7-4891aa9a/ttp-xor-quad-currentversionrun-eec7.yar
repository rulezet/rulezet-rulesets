rule TTP_XOR_QUAD_CurrentVersionRun_eec7 {
  strings:
    $key_eec7 = { bd a8 [2] 99 a6 [2] b2 8a [2] 9c a8 [2] 88 b3 [2] 87 a9 [2] 99 b4 [2] 9b b5 [2] 80 b3 [2] 9c b4 [2] 80 9b }

  condition:
    any of them
}