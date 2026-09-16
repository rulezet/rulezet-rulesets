rule TTP_XOR_QUAD_CurrentVersionRun_ecd0 {
  strings:
    $key_ecd0 = { bf bf [2] 9b b1 [2] b0 9d [2] 9e bf [2] 8a a4 [2] 85 be [2] 9b a3 [2] 99 a2 [2] 82 a4 [2] 9e a3 [2] 82 8c }

  condition:
    any of them
}