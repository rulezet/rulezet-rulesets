rule TTP_XOR_QUAD_CurrentVersionRun_54a5 {
  strings:
    $key_54a5 = { 07 ca [2] 23 c4 [2] 08 e8 [2] 26 ca [2] 32 d1 [2] 3d cb [2] 23 d6 [2] 21 d7 [2] 3a d1 [2] 26 d6 [2] 3a f9 }

  condition:
    any of them
}