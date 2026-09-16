rule TTP_XOR_QUAD_CurrentVersionRun_09a6 {
  strings:
    $key_09a6 = { 5a c9 [2] 7e c7 [2] 55 eb [2] 7b c9 [2] 6f d2 [2] 60 c8 [2] 7e d5 [2] 7c d4 [2] 67 d2 [2] 7b d5 [2] 67 fa }

  condition:
    any of them
}