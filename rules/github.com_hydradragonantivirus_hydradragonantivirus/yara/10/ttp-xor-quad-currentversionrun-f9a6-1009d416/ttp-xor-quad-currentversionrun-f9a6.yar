rule TTP_XOR_QUAD_CurrentVersionRun_f9a6 {
  strings:
    $key_f9a6 = { aa c9 [2] 8e c7 [2] a5 eb [2] 8b c9 [2] 9f d2 [2] 90 c8 [2] 8e d5 [2] 8c d4 [2] 97 d2 [2] 8b d5 [2] 97 fa }

  condition:
    any of them
}