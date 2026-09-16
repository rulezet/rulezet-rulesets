rule TTP_XOR_QUAD_CurrentVersionRun_57a4 {
  strings:
    $key_57a4 = { 04 cb [2] 20 c5 [2] 0b e9 [2] 25 cb [2] 31 d0 [2] 3e ca [2] 20 d7 [2] 22 d6 [2] 39 d0 [2] 25 d7 [2] 39 f8 }

  condition:
    any of them
}