rule TTP_XOR_QUAD_CurrentVersionRun_5da5 {
  strings:
    $key_5da5 = { 0e ca [2] 2a c4 [2] 01 e8 [2] 2f ca [2] 3b d1 [2] 34 cb [2] 2a d6 [2] 28 d7 [2] 33 d1 [2] 2f d6 [2] 33 f9 }

  condition:
    any of them
}