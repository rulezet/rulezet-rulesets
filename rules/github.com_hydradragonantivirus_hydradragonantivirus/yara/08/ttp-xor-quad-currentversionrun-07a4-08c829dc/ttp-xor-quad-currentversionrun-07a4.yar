rule TTP_XOR_QUAD_CurrentVersionRun_07a4 {
  strings:
    $key_07a4 = { 54 cb [2] 70 c5 [2] 5b e9 [2] 75 cb [2] 61 d0 [2] 6e ca [2] 70 d7 [2] 72 d6 [2] 69 d0 [2] 75 d7 [2] 69 f8 }

  condition:
    any of them
}