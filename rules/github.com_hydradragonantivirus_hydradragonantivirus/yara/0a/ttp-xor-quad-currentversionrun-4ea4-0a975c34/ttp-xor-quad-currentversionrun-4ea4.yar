rule TTP_XOR_QUAD_CurrentVersionRun_4ea4 {
  strings:
    $key_4ea4 = { 1d cb [2] 39 c5 [2] 12 e9 [2] 3c cb [2] 28 d0 [2] 27 ca [2] 39 d7 [2] 3b d6 [2] 20 d0 [2] 3c d7 [2] 20 f8 }

  condition:
    any of them
}