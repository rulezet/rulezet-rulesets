rule TTP_XOR_QUAD_CurrentVersionRun_75a5 {
  strings:
    $key_75a5 = { 26 ca [2] 02 c4 [2] 29 e8 [2] 07 ca [2] 13 d1 [2] 1c cb [2] 02 d6 [2] 00 d7 [2] 1b d1 [2] 07 d6 [2] 1b f9 }

  condition:
    any of them
}