rule TTP_XOR_QUAD_CurrentVersionRun_47a4 {
  strings:
    $key_47a4 = { 14 cb [2] 30 c5 [2] 1b e9 [2] 35 cb [2] 21 d0 [2] 2e ca [2] 30 d7 [2] 32 d6 [2] 29 d0 [2] 35 d7 [2] 29 f8 }

  condition:
    any of them
}