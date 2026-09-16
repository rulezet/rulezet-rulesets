rule TTP_XOR_QUAD_CurrentVersionRun_19a6 {
  strings:
    $key_19a6 = { 4a c9 [2] 6e c7 [2] 45 eb [2] 6b c9 [2] 7f d2 [2] 70 c8 [2] 6e d5 [2] 6c d4 [2] 77 d2 [2] 6b d5 [2] 77 fa }

  condition:
    any of them
}