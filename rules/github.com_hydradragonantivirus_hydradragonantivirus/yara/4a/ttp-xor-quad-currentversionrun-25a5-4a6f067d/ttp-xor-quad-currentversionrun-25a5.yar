rule TTP_XOR_QUAD_CurrentVersionRun_25a5 {
  strings:
    $key_25a5 = { 76 ca [2] 52 c4 [2] 79 e8 [2] 57 ca [2] 43 d1 [2] 4c cb [2] 52 d6 [2] 50 d7 [2] 4b d1 [2] 57 d6 [2] 4b f9 }

  condition:
    any of them
}