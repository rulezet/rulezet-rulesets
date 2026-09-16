rule TTP_XOR_QUAD_CurrentVersionRun_0ea4 {
  strings:
    $key_0ea4 = { 5d cb [2] 79 c5 [2] 52 e9 [2] 7c cb [2] 68 d0 [2] 67 ca [2] 79 d7 [2] 7b d6 [2] 60 d0 [2] 7c d7 [2] 60 f8 }

  condition:
    any of them
}