rule TTP_XOR_QUAD_CurrentVersionRun_46a4 {
  strings:
    $key_46a4 = { 15 cb [2] 31 c5 [2] 1a e9 [2] 34 cb [2] 20 d0 [2] 2f ca [2] 31 d7 [2] 33 d6 [2] 28 d0 [2] 34 d7 [2] 28 f8 }

  condition:
    any of them
}