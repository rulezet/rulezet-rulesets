rule TTP_XOR_QUAD_CurrentVersionRun_2da5 {
  strings:
    $key_2da5 = { 7e ca [2] 5a c4 [2] 71 e8 [2] 5f ca [2] 4b d1 [2] 44 cb [2] 5a d6 [2] 58 d7 [2] 43 d1 [2] 5f d6 [2] 43 f9 }

  condition:
    any of them
}