rule TTP_XOR_QUAD_CurrentVersionRun_eeca {
  strings:
    $key_eeca = { bd a5 [2] 99 ab [2] b2 87 [2] 9c a5 [2] 88 be [2] 87 a4 [2] 99 b9 [2] 9b b8 [2] 80 be [2] 9c b9 [2] 80 96 }

  condition:
    any of them
}