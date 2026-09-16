rule TTP_XOR_QUAD_CurrentVersionRun_1ca6 {
  strings:
    $key_1ca6 = { 4f c9 [2] 6b c7 [2] 40 eb [2] 6e c9 [2] 7a d2 [2] 75 c8 [2] 6b d5 [2] 69 d4 [2] 72 d2 [2] 6e d5 [2] 72 fa }

  condition:
    any of them
}