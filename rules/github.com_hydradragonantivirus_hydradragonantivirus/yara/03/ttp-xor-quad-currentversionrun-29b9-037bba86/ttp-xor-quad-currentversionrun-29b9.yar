rule TTP_XOR_QUAD_CurrentVersionRun_29b9 {
  strings:
    $key_29b9 = { 7a d6 [2] 5e d8 [2] 75 f4 [2] 5b d6 [2] 4f cd [2] 40 d7 [2] 5e ca [2] 5c cb [2] 47 cd [2] 5b ca [2] 47 e5 }

  condition:
    any of them
}