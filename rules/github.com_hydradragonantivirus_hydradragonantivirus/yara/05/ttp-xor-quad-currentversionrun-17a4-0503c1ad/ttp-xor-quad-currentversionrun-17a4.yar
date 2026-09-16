rule TTP_XOR_QUAD_CurrentVersionRun_17a4 {
  strings:
    $key_17a4 = { 44 cb [2] 60 c5 [2] 4b e9 [2] 65 cb [2] 71 d0 [2] 7e ca [2] 60 d7 [2] 62 d6 [2] 79 d0 [2] 65 d7 [2] 79 f8 }

  condition:
    any of them
}