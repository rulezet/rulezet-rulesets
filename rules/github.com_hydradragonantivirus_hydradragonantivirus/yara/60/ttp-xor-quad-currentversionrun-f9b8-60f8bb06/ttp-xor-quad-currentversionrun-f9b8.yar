rule TTP_XOR_QUAD_CurrentVersionRun_f9b8 {
  strings:
    $key_f9b8 = { aa d7 [2] 8e d9 [2] a5 f5 [2] 8b d7 [2] 9f cc [2] 90 d6 [2] 8e cb [2] 8c ca [2] 97 cc [2] 8b cb [2] 97 e4 }

  condition:
    any of them
}