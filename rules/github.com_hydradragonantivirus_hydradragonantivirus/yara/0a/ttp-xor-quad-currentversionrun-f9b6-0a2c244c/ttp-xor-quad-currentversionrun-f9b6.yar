rule TTP_XOR_QUAD_CurrentVersionRun_f9b6 {
  strings:
    $key_f9b6 = { aa d9 [2] 8e d7 [2] a5 fb [2] 8b d9 [2] 9f c2 [2] 90 d8 [2] 8e c5 [2] 8c c4 [2] 97 c2 [2] 8b c5 [2] 97 ea }

  condition:
    any of them
}