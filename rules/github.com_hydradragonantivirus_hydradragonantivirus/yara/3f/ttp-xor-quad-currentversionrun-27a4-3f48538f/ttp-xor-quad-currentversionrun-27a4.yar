rule TTP_XOR_QUAD_CurrentVersionRun_27a4 {
  strings:
    $key_27a4 = { 74 cb [2] 50 c5 [2] 7b e9 [2] 55 cb [2] 41 d0 [2] 4e ca [2] 50 d7 [2] 52 d6 [2] 49 d0 [2] 55 d7 [2] 49 f8 }

  condition:
    any of them
}