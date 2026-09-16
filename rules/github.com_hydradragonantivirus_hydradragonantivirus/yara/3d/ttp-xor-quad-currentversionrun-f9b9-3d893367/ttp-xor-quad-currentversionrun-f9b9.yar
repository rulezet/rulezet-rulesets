rule TTP_XOR_QUAD_CurrentVersionRun_f9b9 {
  strings:
    $key_f9b9 = { aa d6 [2] 8e d8 [2] a5 f4 [2] 8b d6 [2] 9f cd [2] 90 d7 [2] 8e ca [2] 8c cb [2] 97 cd [2] 8b ca [2] 97 e5 }

  condition:
    any of them
}