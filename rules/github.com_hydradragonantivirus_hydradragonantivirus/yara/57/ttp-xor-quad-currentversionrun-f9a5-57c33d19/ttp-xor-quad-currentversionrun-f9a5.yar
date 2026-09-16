rule TTP_XOR_QUAD_CurrentVersionRun_f9a5 {
  strings:
    $key_f9a5 = { aa ca [2] 8e c4 [2] a5 e8 [2] 8b ca [2] 9f d1 [2] 90 cb [2] 8e d6 [2] 8c d7 [2] 97 d1 [2] 8b d6 [2] 97 f9 }

  condition:
    any of them
}