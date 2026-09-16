rule TTP_XOR_QUAD_CurrentVersionRun_39b9 {
  strings:
    $key_39b9 = { 6a d6 [2] 4e d8 [2] 65 f4 [2] 4b d6 [2] 5f cd [2] 50 d7 [2] 4e ca [2] 4c cb [2] 57 cd [2] 4b ca [2] 57 e5 }

  condition:
    any of them
}