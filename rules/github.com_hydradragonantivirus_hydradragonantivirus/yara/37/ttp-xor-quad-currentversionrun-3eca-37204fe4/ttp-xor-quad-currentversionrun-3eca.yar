rule TTP_XOR_QUAD_CurrentVersionRun_3eca {
  strings:
    $key_3eca = { 6d a5 [2] 49 ab [2] 62 87 [2] 4c a5 [2] 58 be [2] 57 a4 [2] 49 b9 [2] 4b b8 [2] 50 be [2] 4c b9 [2] 50 96 }

  condition:
    any of them
}