rule TTP_XOR_QUAD_CurrentVersionRun_19b9 {
  strings:
    $key_19b9 = { 4a d6 [2] 6e d8 [2] 45 f4 [2] 6b d6 [2] 7f cd [2] 70 d7 [2] 6e ca [2] 6c cb [2] 77 cd [2] 6b ca [2] 77 e5 }

  condition:
    any of them
}