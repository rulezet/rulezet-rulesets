rule TTP_XOR_QUAD_CurrentVersionRun_49b9 {
  strings:
    $key_49b9 = { 1a d6 [2] 3e d8 [2] 15 f4 [2] 3b d6 [2] 2f cd [2] 20 d7 [2] 3e ca [2] 3c cb [2] 27 cd [2] 3b ca [2] 27 e5 }

  condition:
    any of them
}