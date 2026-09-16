rule TTP_XOR_QUAD_CurrentVersionRun_eca6 {
  strings:
    $key_eca6 = { bf c9 [2] 9b c7 [2] b0 eb [2] 9e c9 [2] 8a d2 [2] 85 c8 [2] 9b d5 [2] 99 d4 [2] 82 d2 [2] 9e d5 [2] 82 fa }

  condition:
    any of them
}