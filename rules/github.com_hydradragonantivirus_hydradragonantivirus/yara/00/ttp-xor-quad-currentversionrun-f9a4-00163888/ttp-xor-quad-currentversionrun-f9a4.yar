rule TTP_XOR_QUAD_CurrentVersionRun_f9a4 {
  strings:
    $key_f9a4 = { aa cb [2] 8e c5 [2] a5 e9 [2] 8b cb [2] 9f d0 [2] 90 ca [2] 8e d7 [2] 8c d6 [2] 97 d0 [2] 8b d7 [2] 97 f8 }

  condition:
    any of them
}