rule TTP_XOR_QUAD_CurrentVersionRun_56a4 {
  strings:
    $key_56a4 = { 05 cb [2] 21 c5 [2] 0a e9 [2] 24 cb [2] 30 d0 [2] 3f ca [2] 21 d7 [2] 23 d6 [2] 38 d0 [2] 24 d7 [2] 38 f8 }

  condition:
    any of them
}