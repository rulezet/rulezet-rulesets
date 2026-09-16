rule TTP_XOR_QUAD_CurrentVersionRun_19b4 {
  strings:
    $key_19b4 = { 4a db [2] 6e d5 [2] 45 f9 [2] 6b db [2] 7f c0 [2] 70 da [2] 6e c7 [2] 6c c6 [2] 77 c0 [2] 6b c7 [2] 77 e8 }

  condition:
    any of them
}