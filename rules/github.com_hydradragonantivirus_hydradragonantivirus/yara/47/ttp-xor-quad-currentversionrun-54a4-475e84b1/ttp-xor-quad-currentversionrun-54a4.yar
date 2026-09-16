rule TTP_XOR_QUAD_CurrentVersionRun_54a4 {
  strings:
    $key_54a4 = { 07 cb [2] 23 c5 [2] 08 e9 [2] 26 cb [2] 32 d0 [2] 3d ca [2] 23 d7 [2] 21 d6 [2] 3a d0 [2] 26 d7 [2] 3a f8 }

  condition:
    any of them
}