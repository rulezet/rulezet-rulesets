rule TTP_XOR_QUAD_CurrentVersionRun_19a5 {
  strings:
    $key_19a5 = { 4a ca [2] 6e c4 [2] 45 e8 [2] 6b ca [2] 7f d1 [2] 70 cb [2] 6e d6 [2] 6c d7 [2] 77 d1 [2] 6b d6 [2] 77 f9 }

  condition:
    any of them
}