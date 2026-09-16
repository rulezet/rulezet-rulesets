rule TTP_XOR_QUAD_CurrentVersionRun_1ea4 {
  strings:
    $key_1ea4 = { 4d cb [2] 69 c5 [2] 42 e9 [2] 6c cb [2] 78 d0 [2] 77 ca [2] 69 d7 [2] 6b d6 [2] 70 d0 [2] 6c d7 [2] 70 f8 }

  condition:
    any of them
}