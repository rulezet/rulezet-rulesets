rule TTP_XOR_QUAD_CurrentVersionRun_6da5 {
  strings:
    $key_6da5 = { 3e ca [2] 1a c4 [2] 31 e8 [2] 1f ca [2] 0b d1 [2] 04 cb [2] 1a d6 [2] 18 d7 [2] 03 d1 [2] 1f d6 [2] 03 f9 }

  condition:
    any of them
}